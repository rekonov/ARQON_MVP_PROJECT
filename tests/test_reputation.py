"""Tests for arqon_guardian.reputation module."""

from __future__ import annotations

from pathlib import Path

import pytest

from arqon_guardian.reputation import (
    AssessmentCache,
    LocalReputationProvider,
    ReputationAssessment,
    ReputationService,
    _host_matches,
    _merge_assessments,
    _normalize_reasons,
)


# ── LocalReputationProvider ──────────────────────────────────────────


class TestLocalReputationProvider:
    def test_blocked_domain_triggers_hard_block(self):
        provider = LocalReputationProvider({"blocked_domains": ["evil.com"]})
        result = provider.evaluate_url("https://evil.com/malware", "evil.com")
        assert result.hard_block is True
        assert any("blocked_domain" in r for r in result.reasons)

    def test_subdomain_of_blocked_domain_triggers_hard_block(self):
        provider = LocalReputationProvider({"blocked_domains": ["evil.com"]})
        result = provider.evaluate_url("https://sub.evil.com/x", "sub.evil.com")
        assert result.hard_block is True

    def test_trusted_domain_reduces_risk(self):
        provider = LocalReputationProvider({"trusted_domains": ["github.com"]})
        result = provider.evaluate_url("https://github.com/repo", "github.com")
        assert result.risk_delta < 0
        assert any("trusted_domain" in r for r in result.reasons)

    def test_suspicious_keywords_increase_risk(self):
        provider = LocalReputationProvider({"suspicious_keywords": ["crack", "keygen"]})
        result = provider.evaluate_url("https://example.com/crack-download", "example.com")
        assert result.risk_delta > 0
        assert any("suspicious_keyword" in r for r in result.reasons)

    def test_keyword_limit_caps_at_three(self):
        provider = LocalReputationProvider(
            {"suspicious_keywords": ["a", "b", "c", "d", "e"]}
        )
        result = provider.evaluate_url("https://a.b.c.d.e.com", "a.b.c.d.e.com")
        keyword_reasons = [r for r in result.reasons if "suspicious_keyword" in r]
        assert len(keyword_reasons) <= 3

    def test_evaluate_file_with_allowed_hash(self):
        provider = LocalReputationProvider(
            {"allowed_hashes": ["abc123"]}
        )
        result = provider.evaluate_file(Path("test.exe"), "abc123")
        assert result.risk_delta < 0
        assert any("allowlisted" in r for r in result.reasons)

    def test_evaluate_file_with_blocked_hash(self):
        provider = LocalReputationProvider(
            {"blocked_hashes": ["deadbeef"]}
        )
        result = provider.evaluate_file(Path("malware.exe"), "deadbeef")
        assert result.hard_block is True

    def test_evaluate_file_suspicious_filename(self):
        provider = LocalReputationProvider(
            {"suspicious_keywords": ["crack"]}
        )
        result = provider.evaluate_file(Path("crack.exe"), None)
        assert result.risk_delta > 0

    def test_empty_config_is_benign(self):
        provider = LocalReputationProvider({})
        url_result = provider.evaluate_url("https://safe.com", "safe.com")
        file_result = provider.evaluate_file(Path("clean.txt"), "aaa")
        assert url_result.risk_delta == 0
        assert url_result.hard_block is False
        assert file_result.risk_delta == 0


# ── ReputationService ────────────────────────────────────────────────


class TestReputationService:
    def test_disabled_service_returns_empty(self):
        svc = ReputationService({"enabled": False})
        result = svc.evaluate_url("https://evil.com", "evil.com")
        assert result.risk_delta == 0
        assert result.reasons == []

    def test_local_provider_mode(self):
        svc = ReputationService({
            "enabled": True,
            "provider": "local",
            "local": {"blocked_domains": ["evil.com"]},
        })
        result = svc.evaluate_url("https://evil.com", "evil.com")
        assert result.hard_block is True

    def test_caching_returns_same_result(self):
        svc = ReputationService({
            "enabled": True,
            "provider": "local",
            "local": {"blocked_domains": ["evil.com"]},
            "cache": {"enabled": True, "ttl_sec": 60},
        })
        r1 = svc.evaluate_url("https://evil.com", "evil.com")
        r2 = svc.evaluate_url("https://evil.com", "evil.com")
        assert r1.hard_block == r2.hard_block
        # Second call should come from cache
        assert "cache" in r2.provider_details

    def test_file_evaluation_with_local(self):
        svc = ReputationService({
            "enabled": True,
            "provider": "local",
            "local": {"blocked_hashes": ["abc"]},
        })
        result = svc.evaluate_file(Path("test.exe"), "abc")
        assert result.hard_block is True


# ── AssessmentCache ──────────────────────────────────────────────────


class TestAssessmentCache:
    def test_cache_hit(self):
        cache = AssessmentCache(enabled=True, ttl_sec=60, max_entries=10)
        assessment = ReputationAssessment(risk_delta=5, reasons=["test"])
        cache.set("key1", assessment)
        result = cache.get("key1")
        assert result is not None
        assert result.risk_delta == 5

    def test_cache_miss(self):
        cache = AssessmentCache(enabled=True, ttl_sec=60, max_entries=10)
        assert cache.get("nonexistent") is None

    def test_disabled_cache_always_misses(self):
        cache = AssessmentCache(enabled=False, ttl_sec=60, max_entries=10)
        cache.set("key1", ReputationAssessment(risk_delta=5))
        assert cache.get("key1") is None

    def test_eviction_when_full(self):
        cache = AssessmentCache(enabled=True, ttl_sec=60, max_entries=2)
        cache.set("a", ReputationAssessment(risk_delta=1))
        cache.set("b", ReputationAssessment(risk_delta=2))
        cache.set("c", ReputationAssessment(risk_delta=3))
        # "a" should have been evicted (oldest)
        assert cache.get("a") is None
        assert cache.get("c") is not None


# ── Helper functions ─────────────────────────────────────────────────


class TestHostMatches:
    def test_exact_match(self):
        assert _host_matches("evil.com", "evil.com") is True

    def test_subdomain_match(self):
        assert _host_matches("sub.evil.com", "evil.com") is True

    def test_no_match(self):
        assert _host_matches("safe.com", "evil.com") is False

    def test_partial_no_match(self):
        assert _host_matches("notevil.com", "evil.com") is False

    def test_empty_strings(self):
        assert _host_matches("", "evil.com") is False
        assert _host_matches("evil.com", "") is False


class TestMergeAssessments:
    def test_merges_risk_deltas(self):
        a = ReputationAssessment(risk_delta=10, reasons=["a"])
        b = ReputationAssessment(risk_delta=20, reasons=["b"])
        result = _merge_assessments([a, b])
        assert result.risk_delta == 30
        assert "a" in result.reasons
        assert "b" in result.reasons

    def test_hard_block_propagates(self):
        a = ReputationAssessment(hard_block=True)
        b = ReputationAssessment(hard_block=False)
        assert _merge_assessments([a, b]).hard_block is True

    def test_empty_list(self):
        result = _merge_assessments([])
        assert result.risk_delta == 0
        assert result.hard_block is False


class TestNormalizeReasons:
    def test_list_input(self):
        assert _normalize_reasons(["a", "b"], None) == ["a", "b"]

    def test_string_primary(self):
        assert _normalize_reasons("single", None) == ["single"]

    def test_fallback_used(self):
        assert _normalize_reasons(None, "fallback") == ["fallback"]

    def test_empty_returns_empty(self):
        assert _normalize_reasons(None, None) == []
