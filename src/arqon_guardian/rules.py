from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import logging
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import parse_qs, urlparse
import zipfile

from arqon_guardian.reputation import ReputationService
from arqon_guardian.signature import SignatureInspector


LOGGER = logging.getLogger(__name__)

SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}
LOLBIN_ABUSE_TOKENS = [
    "-enc",
    "--encodedcommand",
    "downloadstring",
    "invoke-webrequest",
    "iwr ",
    "frombase64string",
    "iex ",
    "invoke-expression",
    "reg add ",
    "schtasks",
    "rundll32",
    "regsvr32",
    "mshta",
    "http://",
    "https://",
]


@dataclass(slots=True)
class Decision:
    action: str
    reasons: list[str]
    risk_score: int = 0
    sha256: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def should_block(self) -> bool:
        return self.action == "block"

    @property
    def is_warning(self) -> bool:
        return self.action == "warn"


class RuleEvaluator:
    def __init__(
        self,
        rules_config: dict[str, Any],
        risk_config: dict[str, Any] | None = None,
        reputation_service: ReputationService | None = None,
        signature_inspector: SignatureInspector | None = None,
    ):
        self.blocked_process_names = {
            str(item).strip().lower() for item in rules_config.get("blocked_process_names", [])
        }
        self.lolbin_process_names = {
            str(item).strip().lower() for item in rules_config.get("lolbin_process_names", [])
        }
        self.suspicious_cmdline_patterns = _compile_patterns(
            rules_config.get("suspicious_cmdline_patterns", [])
        )

        self.blocked_extensions = {
            str(item).strip().lower() for item in rules_config.get("blocked_extensions", [])
        }
        self.high_risk_download_extensions = {
            str(item).strip().lower() for item in rules_config.get("high_risk_download_extensions", [])
        }
        self.blocked_hashes = {
            str(item).strip().lower() for item in rules_config.get("blocked_hashes", [])
        }
        self.allowed_hashes = {
            str(item).strip().lower() for item in rules_config.get("allowed_hashes", [])
        }
        self.suspicious_name_patterns = _compile_patterns(
            rules_config.get("suspicious_name_patterns", [])
        )
        self.blocked_url_patterns = _compile_patterns(rules_config.get("blocked_url_patterns", []))
        self.suspicious_url_patterns = _compile_patterns(rules_config.get("suspicious_url_patterns", []))

        self.archive_scan_enabled = bool(rules_config.get("archive_scan_enabled", True))
        self.archive_scan_max_entries = max(1, int(rules_config.get("archive_scan_max_entries", 256)))
        archive_max_mb = float(rules_config.get("archive_scan_max_total_uncompressed_mb", 128))
        self.archive_scan_max_total_uncompressed_bytes = int(max(1.0, archive_max_mb) * 1024 * 1024)

        self.script_analysis_enabled = bool(rules_config.get("script_analysis_enabled", True))
        self.script_analysis_max_bytes = max(512, int(rules_config.get("script_analysis_max_bytes", 262_144)))
        self.suspicious_script_patterns = _compile_patterns(
            rules_config.get("suspicious_script_patterns", [])
        )

        rcfg = risk_config or {}
        self.block_threshold = _coerce_threshold(rcfg.get("block_threshold"), 70)
        self.warn_threshold = _coerce_threshold(rcfg.get("warn_threshold"), 40)
        if self.warn_threshold > self.block_threshold:
            self.warn_threshold = self.block_threshold

        self.reputation = reputation_service or ReputationService({})
        self.signature_inspector = signature_inspector or SignatureInspector()

    def evaluate_process(
        self,
        process_name: str | None,
        process_exe: str | None,
        cmdline: Iterable[str] | None,
    ) -> Decision:
        reasons: list[str] = []
        risk = 0
        forced_block = False
        details: dict[str, Any] = {}

        normalized_name = (process_name or "").strip().lower()
        if normalized_name and normalized_name in self.blocked_process_names:
            forced_block = True
            reasons.append(f"blocked_process_name:{normalized_name}")

        if process_exe:
            exe_name = Path(process_exe).name.strip().lower()
            if exe_name in self.blocked_process_names:
                forced_block = True
                reasons.append(f"blocked_process_exe:{exe_name}")
            if _is_temp_or_user_writable_path(process_exe):
                risk += 24
                reasons.append("process_from_suspicious_path")

        cmdline_parts = list(cmdline or [])
        joined_cmd = " ".join(cmdline_parts)
        joined_cmd_lower = joined_cmd.lower()
        details["cmdline_length"] = len(joined_cmd)

        for pattern in self.suspicious_cmdline_patterns:
            if pattern.search(joined_cmd):
                risk += 44
                reasons.append(f"suspicious_cmdline_pattern:{pattern.pattern}")

        for pattern in self.suspicious_name_patterns:
            if pattern.search(joined_cmd):
                risk += 75
                reasons.append(f"suspicious_cmdline:{pattern.pattern}")

        if normalized_name and normalized_name in self.lolbin_process_names:
            if _contains_any(joined_cmd_lower, LOLBIN_ABUSE_TOKENS):
                risk += 62
                reasons.append(f"lolbin_abuse:{normalized_name}")
            elif joined_cmd.strip():
                risk += 8
                reasons.append(f"lolbin_activity:{normalized_name}")

        if not reasons:
            reasons.append("process_ok")

        details["process_name"] = normalized_name or "unknown"
        return self._finalize_decision(
            risk=risk,
            reasons=reasons,
            forced_block=forced_block,
            details=details,
        )

    def evaluate_file(self, path: Path) -> Decision:
        if not path.exists() or not path.is_file():
            return Decision(action="allow", reasons=["file_not_found"], risk_score=0)

        sha256 = compute_sha256(path)
        lowered_hash = sha256.lower()

        if lowered_hash in self.allowed_hashes:
            return Decision(
                action="allow",
                reasons=["hash_allowlisted"],
                risk_score=0,
                sha256=sha256,
            )

        if lowered_hash in self.blocked_hashes:
            return Decision(
                action="block",
                reasons=["hash_blocklisted"],
                risk_score=100,
                sha256=sha256,
            )

        reasons: list[str] = []
        risk = 0
        forced_block = False
        details: dict[str, Any] = {}

        extension = path.suffix.lower()
        if extension and extension in self.blocked_extensions:
            risk += 78
            reasons.append(f"blocked_extension:{extension}")

        if extension and extension in self.high_risk_download_extensions:
            risk += 18
            reasons.append(f"high_risk_extension:{extension}")

        filename = path.name
        for pattern in self.suspicious_name_patterns:
            if pattern.search(filename):
                risk += 42
                reasons.append(f"suspicious_filename:{pattern.pattern}")

        if self.script_analysis_enabled and extension in SCRIPT_EXTENSIONS:
            script_findings = _analyze_script_content(
                path=path,
                max_bytes=self.script_analysis_max_bytes,
                patterns=self.suspicious_script_patterns,
            )
            risk += script_findings["risk"]
            reasons.extend(script_findings["reasons"])
            details["script_analysis"] = script_findings["details"]

        if self.archive_scan_enabled and extension in ARCHIVE_EXTENSIONS:
            archive_findings = self._analyze_archive(path, extension)
            risk += archive_findings["risk"]
            reasons.extend(archive_findings["reasons"])
            details["archive_analysis"] = archive_findings["details"]

        signature = self.signature_inspector.inspect(path)
        details["signature_status"] = signature.status
        if signature.signer:
            details["signer"] = signature.signer
        if signature.status == "Valid":
            risk -= 20
            reasons.append("valid_signature")
        elif signature.status in {"NotSigned", "NotSupportedFileFormat"}:
            risk += 32
            reasons.append(f"unsigned_file:{signature.status}")
        elif signature.status not in {"Skipped", "UnsupportedOS"}:
            risk += 45
            reasons.append(f"untrusted_signature:{signature.status}")

        rep = self.reputation.evaluate_file(path, sha256)
        risk += rep.risk_delta
        reasons.extend(rep.reasons)
        forced_block = forced_block or rep.hard_block
        if rep.provider_details:
            details["reputation"] = rep.provider_details

        if not reasons:
            reasons.append("file_ok")

        return self._finalize_decision(
            risk=risk,
            reasons=reasons,
            forced_block=forced_block,
            sha256=sha256,
            details=details,
        )

    def evaluate_url(self, url: str) -> Decision:
        candidate = (url or "").strip()
        if not candidate:
            return Decision(action="block", reasons=["empty_url"], risk_score=100)

        parsed = urlparse(candidate)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()

        reasons: list[str] = []
        risk = 0
        forced_block = False
        details: dict[str, Any] = {
            "scheme": scheme or "",
            "host": host or "",
        }

        if scheme not in {"http", "https"}:
            risk += 95
            reasons.append(f"unsupported_scheme:{scheme or 'missing'}")

        if not host:
            risk += 90
            reasons.append("missing_host")
        else:
            if _is_ip_host(host):
                if _is_private_or_local_host(host):
                    risk += 8
                    reasons.append("private_ip_host")
                else:
                    risk += 32
                    reasons.append("public_ip_host")

            if "xn--" in host:
                risk += 24
                reasons.append("punycode_domain")

        if scheme == "http" and host and not _is_private_or_local_host(host):
            risk += 26
            reasons.append("unencrypted_http")

        for pattern in self.blocked_url_patterns:
            if pattern.search(candidate):
                forced_block = True
                reasons.append(f"blocked_url_pattern:{pattern.pattern}")

        for pattern in self.suspicious_url_patterns:
            if pattern.search(candidate):
                risk += 30
                reasons.append(f"suspicious_url_pattern:{pattern.pattern}")

        download_ext = Path(parsed.path).suffix.lower()
        if download_ext and download_ext in self.high_risk_download_extensions:
            risk += 22
            reasons.append(f"high_risk_download_target:{download_ext}")

        query_map = parse_qs(parsed.query, keep_blank_values=True)
        sensitive_params = {"seed", "privatekey", "passphrase", "wallet", "recovery", "otp", "token"}
        sensitive_hits = sorted(set(query_map.keys()) & sensitive_params)
        if sensitive_hits:
            risk += 35
            reasons.append(f"sensitive_query_params:{','.join(sensitive_hits)}")

        rep = self.reputation.evaluate_url(candidate, host)
        risk += rep.risk_delta
        reasons.extend(rep.reasons)
        forced_block = forced_block or rep.hard_block
        if rep.provider_details:
            details["reputation"] = rep.provider_details

        if not reasons:
            reasons.append("url_ok")

        return self._finalize_decision(
            risk=risk,
            reasons=reasons,
            forced_block=forced_block,
            details=details,
        )

    def _analyze_archive(self, path: Path, extension: str) -> dict[str, Any]:
        if extension != ".zip":
            return {
                "risk": 16,
                "reasons": [f"archive_unscanned_format:{extension}"],
                "details": {
                    "format": extension,
                    "scanned": False,
                },
            }
        return self._analyze_zip_archive(path)

    def _analyze_zip_archive(self, path: Path) -> dict[str, Any]:
        risk = 0
        reasons: list[str] = []
        details: dict[str, Any] = {"format": ".zip", "scanned": True}

        try:
            with zipfile.ZipFile(path, "r") as zf:
                members = zf.infolist()
                total_entries = len(members)
                details["entries_total"] = total_entries

                if total_entries > self.archive_scan_max_entries:
                    risk += 18
                    reasons.append("archive_too_many_entries")

                blocked_hits = 0
                high_risk_hits = 0
                nested_archive_hits = 0
                suspicious_name_hits = 0
                total_uncompressed = 0

                for info in members[: self.archive_scan_max_entries]:
                    if info.is_dir():
                        continue
                    name = info.filename.replace("\\", "/")
                    entry_name = Path(name).name
                    entry_ext = Path(entry_name).suffix.lower()
                    total_uncompressed += max(0, int(info.file_size))

                    if entry_ext in self.blocked_extensions:
                        blocked_hits += 1
                    elif entry_ext in self.high_risk_download_extensions:
                        high_risk_hits += 1

                    if entry_ext in ARCHIVE_EXTENSIONS:
                        nested_archive_hits += 1

                    for pattern in self.suspicious_name_patterns:
                        if pattern.search(entry_name):
                            suspicious_name_hits += 1
                            break

                if blocked_hits > 0:
                    risk += min(95, 72 + max(0, blocked_hits - 1) * 12)
                    reasons.append(f"archive_blocked_entries:{blocked_hits}")
                if high_risk_hits > 0:
                    risk += min(40, high_risk_hits * 8)
                    reasons.append(f"archive_high_risk_entries:{high_risk_hits}")
                if nested_archive_hits > 0:
                    risk += min(30, nested_archive_hits * 10)
                    reasons.append(f"archive_nested_archives:{nested_archive_hits}")
                if suspicious_name_hits > 0:
                    risk += min(30, suspicious_name_hits * 8)
                    reasons.append(f"archive_suspicious_names:{suspicious_name_hits}")
                if total_uncompressed > self.archive_scan_max_total_uncompressed_bytes:
                    risk += 25
                    reasons.append("archive_uncompressed_size_exceeded")

                details.update(
                    {
                        "entries_scanned": min(total_entries, self.archive_scan_max_entries),
                        "blocked_hits": blocked_hits,
                        "high_risk_hits": high_risk_hits,
                        "nested_archive_hits": nested_archive_hits,
                        "suspicious_name_hits": suspicious_name_hits,
                        "total_uncompressed_bytes": total_uncompressed,
                    }
                )
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
            return {
                "risk": 35,
                "reasons": ["archive_corrupt_or_invalid_zip"],
                "details": {"format": ".zip", "scanned": False},
            }

        return {"risk": risk, "reasons": reasons, "details": details}

    def _finalize_decision(
        self,
        risk: int,
        reasons: list[str],
        forced_block: bool = False,
        forced_allow: bool = False,
        sha256: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> Decision:
        score = _clamp_score(risk)
        deduped_reasons = _dedupe(reasons)
        if not deduped_reasons:
            deduped_reasons = ["no_indicators"]

        if forced_allow:
            return Decision(
                action="allow",
                reasons=deduped_reasons,
                risk_score=score,
                sha256=sha256,
                details=details or {},
            )

        if forced_block and score < self.block_threshold:
            score = self.block_threshold

        if forced_block or score >= self.block_threshold:
            action = "block"
        elif score >= self.warn_threshold:
            action = "warn"
        else:
            action = "allow"

        return Decision(
            action=action,
            reasons=deduped_reasons,
            risk_score=score,
            sha256=sha256,
            details=details or {},
        )


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_stream:
        for chunk in iter(lambda: file_stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _analyze_script_content(
    *,
    path: Path,
    max_bytes: int,
    patterns: list[re.Pattern[str]],
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError:
        return {"risk": 8, "reasons": ["script_read_error"], "details": {"readable": False}}

    truncated = False
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        truncated = True

    text = raw.decode("utf-8", errors="ignore")
    lowered = text.lower()

    risk = 0
    reasons: list[str] = []
    pattern_hits = 0
    for pattern in patterns:
        if pattern.search(text):
            pattern_hits += 1
            reasons.append(f"script_pattern:{pattern.pattern}")

    if pattern_hits > 0:
        risk += min(60, pattern_hits * 12)

    has_url = ("http://" in lowered) or ("https://" in lowered)
    has_obfuscation = _contains_any(
        lowered,
        ["frombase64string", "-enc", "char]", "invoke-expression", "iex "],
    )
    has_persistence = _contains_any(
        lowered,
        ["\\run", "schtasks", "startup", "new-itemproperty", "register-scheduledtask"],
    )
    has_lolbin_refs = _contains_any(
        lowered,
        ["rundll32", "regsvr32", "mshta", "wscript", "cscript", "powershell -enc"],
    )
    has_defender_tamper = _contains_any(
        lowered,
        ["set-mppreference", "add-mppreference", "disablerealtimemonitoring"],
    )

    if has_url and has_obfuscation:
        risk += 24
        reasons.append("script_url_and_obfuscation")
    if has_persistence:
        risk += 26
        reasons.append("script_persistence_behavior")
    if has_lolbin_refs:
        risk += 18
        reasons.append("script_lolbin_reference")
    if has_defender_tamper:
        risk += 36
        reasons.append("script_defender_tamper")
    if truncated:
        risk += 6
        reasons.append("script_truncated_analysis")

    details = {
        "readable": True,
        "truncated": truncated,
        "bytes_analyzed": len(raw),
        "pattern_hits": pattern_hits,
        "has_url": has_url,
        "has_obfuscation": has_obfuscation,
        "has_persistence": has_persistence,
        "has_lolbin_refs": has_lolbin_refs,
        "has_defender_tamper": has_defender_tamper,
    }
    return {"risk": risk, "reasons": reasons, "details": details}


def _compile_patterns(items: list[str]) -> list[re.Pattern[str]]:
    compiled: list[re.Pattern[str]] = []
    for raw in items:
        try:
            compiled.append(re.compile(str(raw)))
        except re.error:
            LOGGER.warning("Invalid regex pattern in config: %s", raw)
    return compiled


def _coerce_threshold(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(100, parsed))


def _clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _contains_any(text: str, tokens: list[str]) -> bool:
    for token in tokens:
        if token in text:
            return True
    return False


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_private_or_local_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        addr = ipaddress.ip_address(host)
        return bool(addr.is_private or addr.is_loopback)
    except ValueError:
        return host.endswith(".local")


def _is_temp_or_user_writable_path(process_exe: str) -> bool:
    lowered = process_exe.replace("/", "\\").lower()
    suspicious_segments = [
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
        "\\downloads\\",
    ]
    return any(segment in lowered for segment in suspicious_segments)
