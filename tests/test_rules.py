"""Tests for arqon_guardian.rules module."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from arqon_guardian.reputation import ReputationAssessment, ReputationService
from arqon_guardian.rules import (
    Decision,
    RuleEvaluator,
    compute_sha256,
    _clamp_score,
    _contains_any,
    _dedupe,
    _is_ip_host,
    _is_private_or_local_host,
    _is_temp_or_user_writable_path,
)
from arqon_guardian.signature import SignatureInspector


# ── Decision dataclass ───────────────────────────────────────────────


class TestDecision:
    def test_should_block(self):
        d = Decision(action="block", reasons=["test"], risk_score=80)
        assert d.should_block is True
        assert d.is_warning is False

    def test_is_warning(self):
        d = Decision(action="warn", reasons=["test"], risk_score=50)
        assert d.is_warning is True
        assert d.should_block is False

    def test_allow(self):
        d = Decision(action="allow", reasons=["ok"], risk_score=10)
        assert d.should_block is False
        assert d.is_warning is False


# ── Helper functions ─────────────────────────────────────────────────


class TestHelpers:
    def test_clamp_score(self):
        assert _clamp_score(-10) == 0
        assert _clamp_score(50) == 50
        assert _clamp_score(200) == 100

    def test_contains_any(self):
        assert _contains_any("hello world", ["hello"]) is True
        assert _contains_any("hello world", ["foo"]) is False

    def test_dedupe(self):
        assert _dedupe(["a", "b", "a", "c"]) == ["a", "b", "c"]

    def test_is_ip_host(self):
        assert _is_ip_host("192.168.1.1") is True
        assert _is_ip_host("example.com") is False

    def test_is_private_or_local_host(self):
        assert _is_private_or_local_host("localhost") is True
        assert _is_private_or_local_host("127.0.0.1") is True
        assert _is_private_or_local_host("192.168.1.1") is True
        assert _is_private_or_local_host("8.8.8.8") is False

    def test_is_temp_path(self):
        assert _is_temp_or_user_writable_path(
            r"C:\Users\test\AppData\Local\Temp\malware.exe"
        ) is True
        assert _is_temp_or_user_writable_path(
            r"C:\Program Files\app.exe"
        ) is False


# ── Fixtures ─────────────────────────────────────────────────────────


def _make_evaluator(**overrides) -> RuleEvaluator:
    """Create a RuleEvaluator with mock reputation and signature."""
    rules_config = overrides.pop("rules_config", {})
    risk_config = overrides.pop("risk_config", None)

    mock_rep = MagicMock(spec=ReputationService)
    mock_rep.evaluate_url.return_value = ReputationAssessment()
    mock_rep.evaluate_file.return_value = ReputationAssessment()

    mock_sig = MagicMock(spec=SignatureInspector)
    mock_sig.inspect.return_value = MagicMock(status="Skipped", signer=None)

    return RuleEvaluator(
        rules_config=rules_config,
        risk_config=risk_config,
        reputation_service=mock_rep,
        signature_inspector=mock_sig,
    )


# ── evaluate_process ─────────────────────────────────────────────────


class TestEvaluateProcess:
    def test_blocked_process_name(self):
        ev = _make_evaluator(rules_config={"blocked_process_names": ["mimikatz.exe"]})
        d = ev.evaluate_process("mimikatz.exe", None, None)
        assert d.should_block is True

    def test_allowed_process(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_process("notepad.exe", None, None)
        assert d.should_block is False
        assert "process_ok" in d.reasons

    def test_suspicious_cmdline_pattern(self):
        ev = _make_evaluator(
            rules_config={"suspicious_cmdline_patterns": [r"downloadstring"]}
        )
        d = ev.evaluate_process("powershell.exe", None, ["powershell", "downloadstring('url')"])
        assert d.risk_score > 0
        assert any("suspicious_cmdline_pattern" in r for r in d.reasons)

    def test_lolbin_abuse_detection(self):
        ev = _make_evaluator(
            rules_config={"lolbin_process_names": ["powershell.exe"]}
        )
        d = ev.evaluate_process("powershell.exe", None, ["powershell", "-enc", "base64stuff"])
        assert d.risk_score > 40
        assert any("lolbin_abuse" in r for r in d.reasons)

    def test_process_from_temp_path(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_process(
            "update.exe",
            r"C:\Users\test\AppData\Local\Temp\update.exe",
            None,
        )
        assert any("suspicious_path" in r for r in d.reasons)


# ── evaluate_url ─────────────────────────────────────────────────────


class TestEvaluateUrl:
    def test_empty_url_blocked(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("")
        assert d.should_block is True
        assert "empty_url" in d.reasons

    def test_valid_https_url(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("https://example.com/page")
        assert d.should_block is False

    def test_unsupported_scheme(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("ftp://example.com/file")
        assert d.risk_score > 50

    def test_public_ip_host(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("https://8.8.8.8/api")
        assert any("public_ip_host" in r for r in d.reasons)

    def test_blocked_url_pattern(self):
        ev = _make_evaluator(
            rules_config={"blocked_url_patterns": [r"malware\.xyz"]}
        )
        d = ev.evaluate_url("https://malware.xyz/download")
        assert d.should_block is True

    def test_unencrypted_http(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("http://example.com/page")
        assert any("unencrypted_http" in r for r in d.reasons)

    def test_punycode_domain(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("https://xn--e1afmapc.xn--p1ai/test")
        assert any("punycode_domain" in r for r in d.reasons)

    def test_high_risk_download_extension(self):
        ev = _make_evaluator(
            rules_config={"high_risk_download_extensions": [".exe"]}
        )
        d = ev.evaluate_url("https://example.com/setup.exe")
        assert any("high_risk_download_target" in r for r in d.reasons)

    def test_sensitive_query_params(self):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_url("https://example.com/api?token=abc&privatekey=xyz")
        assert any("sensitive_query_params" in r for r in d.reasons)


# ── evaluate_file ────────────────────────────────────────────────────


class TestEvaluateFile:
    def test_nonexistent_file(self, tmp_path):
        ev = _make_evaluator(rules_config={})
        d = ev.evaluate_file(tmp_path / "ghost.txt")
        assert d.action == "allow"
        assert "file_not_found" in d.reasons

    def test_blocked_hash(self, tmp_path):
        f = tmp_path / "malware.bin"
        f.write_bytes(b"malware content")
        sha = hashlib.sha256(b"malware content").hexdigest()

        ev = _make_evaluator(rules_config={"blocked_hashes": [sha]})
        d = ev.evaluate_file(f)
        assert d.should_block is True
        assert "hash_blocklisted" in d.reasons

    def test_allowed_hash(self, tmp_path):
        f = tmp_path / "safe.bin"
        f.write_bytes(b"safe content")
        sha = hashlib.sha256(b"safe content").hexdigest()

        ev = _make_evaluator(rules_config={"allowed_hashes": [sha]})
        d = ev.evaluate_file(f)
        assert d.action == "allow"
        assert "hash_allowlisted" in d.reasons

    def test_blocked_extension(self, tmp_path):
        f = tmp_path / "payload.scr"
        f.write_bytes(b"data")

        ev = _make_evaluator(rules_config={"blocked_extensions": [".scr"]})
        d = ev.evaluate_file(f)
        assert d.risk_score > 50
        assert any("blocked_extension" in r for r in d.reasons)

    def test_suspicious_filename_pattern(self, tmp_path):
        f = tmp_path / "invoice_2024.exe"
        f.write_bytes(b"data")

        ev = _make_evaluator(
            rules_config={"suspicious_name_patterns": [r"invoice.*\.exe"]}
        )
        d = ev.evaluate_file(f)
        assert any("suspicious_filename" in r for r in d.reasons)


# ── compute_sha256 ───────────────────────────────────────────────────


class TestComputeSha256:
    def test_computes_correct_hash(self, tmp_path):
        f = tmp_path / "test.bin"
        content = b"hello world"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        assert compute_sha256(f) == expected


# ── Risk thresholds ──────────────────────────────────────────────────


class TestRiskThresholds:
    def test_custom_thresholds(self):
        ev = _make_evaluator(
            rules_config={},
            risk_config={"block_threshold": 80, "warn_threshold": 30},
        )
        assert ev.block_threshold == 80
        assert ev.warn_threshold == 30

    def test_warn_threshold_capped_at_block(self):
        ev = _make_evaluator(
            rules_config={},
            risk_config={"block_threshold": 50, "warn_threshold": 60},
        )
        assert ev.warn_threshold <= ev.block_threshold
