from __future__ import annotations

from dataclasses import dataclass, field
import threading
import json
import logging
from pathlib import Path
import time
from typing import Any
from urllib import request


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ReputationAssessment:
    risk_delta: int = 0
    reasons: list[str] = field(default_factory=list)
    hard_block: bool = False
    provider_details: dict[str, Any] = field(default_factory=dict)


class LocalReputationProvider:
    def __init__(self, config: dict[str, Any]):
        self.blocked_domains = {str(item).strip().lower() for item in config.get("blocked_domains", [])}
        self.trusted_domains = {str(item).strip().lower() for item in config.get("trusted_domains", [])}
        self.suspicious_keywords = [
            str(item).strip().lower() for item in config.get("suspicious_keywords", [])
        ]
        self.blocked_hashes = {str(item).strip().lower() for item in config.get("blocked_hashes", [])}
        self.allowed_hashes = {str(item).strip().lower() for item in config.get("allowed_hashes", [])}

    def evaluate_url(self, url: str, host: str) -> ReputationAssessment:
        risk_delta = 0
        reasons: list[str] = []
        hard_block = False

        for blocked in self.blocked_domains:
            if _host_matches(host, blocked):
                hard_block = True
                reasons.append(f"reputation_blocked_domain:{blocked}")
                break

        for trusted in self.trusted_domains:
            if _host_matches(host, trusted):
                risk_delta -= 20
                reasons.append(f"reputation_trusted_domain:{trusted}")
                break

        lowered_url = url.lower()
        keyword_hits = 0
        for keyword in self.suspicious_keywords:
            if keyword and keyword in lowered_url:
                risk_delta += 18
                keyword_hits += 1
                reasons.append(f"reputation_suspicious_keyword:{keyword}")
            if keyword_hits >= 3:
                break

        return ReputationAssessment(
            risk_delta=risk_delta,
            reasons=reasons,
            hard_block=hard_block,
            provider_details={"provider": "local"},
        )

    def evaluate_file(self, path: Path, sha256: str | None) -> ReputationAssessment:
        risk_delta = 0
        reasons: list[str] = []
        hard_block = False

        lowered_hash = (sha256 or "").lower()
        if lowered_hash and lowered_hash in self.allowed_hashes:
            risk_delta -= 30
            reasons.append("reputation_hash_allowlisted")
        if lowered_hash and lowered_hash in self.blocked_hashes:
            hard_block = True
            reasons.append("reputation_hash_blocklisted")

        lowered_name = path.name.lower()
        for keyword in self.suspicious_keywords:
            if keyword and keyword in lowered_name:
                risk_delta += 15
                reasons.append(f"reputation_suspicious_filename_keyword:{keyword}")
                break

        return ReputationAssessment(
            risk_delta=risk_delta,
            reasons=reasons,
            hard_block=hard_block,
            provider_details={"provider": "local"},
        )


class RemoteReputationAdapter:
    def __init__(self, config: dict[str, Any], timeout_sec: float):
        endpoint = str(config.get("endpoint", "")).strip()
        self.enabled = bool(config.get("enabled", False) and endpoint)
        self.endpoint = endpoint.rstrip("/")
        self.api_key = str(config.get("api_key", "")).strip()
        self.timeout_sec = max(0.5, timeout_sec)

    def evaluate_url(self, url: str) -> ReputationAssessment:
        if not self.enabled:
            return ReputationAssessment()
        payload = {"kind": "url", "value": url}
        return self._query(payload)

    def evaluate_hash(self, sha256: str) -> ReputationAssessment:
        if not self.enabled or not sha256:
            return ReputationAssessment()
        payload = {"kind": "sha256", "value": sha256}
        return self._query(payload)

    def _query(self, payload: dict[str, Any]) -> ReputationAssessment:
        data, error = _post_json(
            url=self.endpoint,
            payload=payload,
            timeout_sec=self.timeout_sec,
            api_key=self.api_key,
        )
        if error:
            LOGGER.debug("Remote reputation unavailable: %s", error)
            return ReputationAssessment(provider_details={"provider": "remote", "error": error})

        if not isinstance(data, dict):
            return ReputationAssessment(provider_details={"provider": "remote", "error": "invalid_payload"})

        reasons = _normalize_reasons(data.get("reasons"), data.get("reason"))
        action = str(data.get("action", "")).strip().lower()
        malicious = bool(data.get("malicious", False))
        hard_block = action == "block" or malicious or bool(data.get("hard_block", False))
        risk_delta = _coerce_int(data.get("risk_delta"), 0)

        if hard_block and risk_delta < 70:
            risk_delta = 70

        return ReputationAssessment(
            risk_delta=risk_delta,
            reasons=reasons,
            hard_block=hard_block,
            provider_details={"provider": "remote", "raw": data},
        )


class ReputationService:
    def __init__(self, config: dict[str, Any] | None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.provider_mode = str(cfg.get("provider", "local")).strip().lower() or "local"
        timeout_sec = float(cfg.get("timeout_sec", 2.5))
        self.local = LocalReputationProvider(dict(cfg.get("local", {})))
        self.remote = RemoteReputationAdapter(dict(cfg.get("remote", {})), timeout_sec=timeout_sec)

        cache_cfg = dict(cfg.get("cache", {}))
        self.url_cache = AssessmentCache(
            enabled=bool(cache_cfg.get("enabled", True)),
            ttl_sec=float(cache_cfg.get("ttl_sec", 900)),
            max_entries=int(cache_cfg.get("max_entries", 4096)),
        )
        self.file_cache = AssessmentCache(
            enabled=bool(cache_cfg.get("enabled", True)),
            ttl_sec=float(cache_cfg.get("ttl_sec", 900)),
            max_entries=int(cache_cfg.get("max_entries", 4096)),
        )

    def evaluate_url(self, url: str, host: str) -> ReputationAssessment:
        if not self.enabled:
            return ReputationAssessment()

        cache_key = f"url:{url}"
        cached = self.url_cache.get(cache_key)
        if cached is not None:
            return cached

        parts: list[ReputationAssessment] = []
        if self.provider_mode in {"local", "hybrid"}:
            parts.append(self.local.evaluate_url(url, host))
        if self.provider_mode in {"remote", "hybrid"}:
            parts.append(self.remote.evaluate_url(url))
        result = _merge_assessments(parts)
        self.url_cache.set(cache_key, result)
        return result

    def evaluate_file(self, path: Path, sha256: str | None) -> ReputationAssessment:
        if not self.enabled:
            return ReputationAssessment()

        cache_key = f"file:{(sha256 or str(path)).lower()}"
        cached = self.file_cache.get(cache_key)
        if cached is not None:
            return cached

        parts: list[ReputationAssessment] = []
        if self.provider_mode in {"local", "hybrid"}:
            parts.append(self.local.evaluate_file(path, sha256))
        if self.provider_mode in {"remote", "hybrid"} and sha256:
            parts.append(self.remote.evaluate_hash(sha256))
        result = _merge_assessments(parts)
        self.file_cache.set(cache_key, result)
        return result


def _merge_assessments(items: list[ReputationAssessment]) -> ReputationAssessment:
    risk_delta = 0
    reasons: list[str] = []
    hard_block = False
    details: dict[str, Any] = {}

    for item in items:
        risk_delta += item.risk_delta
        reasons.extend(item.reasons)
        hard_block = hard_block or item.hard_block
        details_key = item.provider_details.get("provider", f"provider_{len(details)}")
        details[str(details_key)] = item.provider_details

    return ReputationAssessment(
        risk_delta=risk_delta,
        reasons=_dedupe(reasons),
        hard_block=hard_block,
        provider_details=details,
    )


def _host_matches(host: str, domain: str) -> bool:
    if not host or not domain:
        return False
    host = host.lower()
    domain = domain.lower()
    return host == domain or host.endswith(f".{domain}")


def _post_json(
    url: str,
    payload: dict[str, Any],
    timeout_sec: float,
    api_key: str,
) -> tuple[Any | None, str | None]:
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = request.Request(url=url, method="POST", data=data, headers=headers)
    opener = request.build_opener(request.ProxyHandler({}))

    last_error: str | None = None
    for attempt in range(2):
        try:
            with opener.open(req, timeout=timeout_sec) as response:
                raw = response.read().decode("utf-8", errors="replace")
                if not raw.strip():
                    return {}, None
                return json.loads(raw), None
        except Exception as error:  # pragma: no cover - network uncertainty
            last_error = str(error)
            if attempt == 0:
                time.sleep(0.05)
                continue
            return None, last_error

    return None, last_error or "unknown_error"


def _normalize_reasons(primary: Any, fallback: Any) -> list[str]:
    if isinstance(primary, list):
        return [str(item) for item in primary if str(item).strip()]
    if isinstance(primary, str) and primary.strip():
        return [primary.strip()]
    if isinstance(fallback, str) and fallback.strip():
        return [fallback.strip()]
    return []


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        output.append(item)
    return output


@dataclass(slots=True)
class CacheEntry:
    value: ReputationAssessment
    expires_at: float
    created_at: float


class AssessmentCache:
    def __init__(self, *, enabled: bool, ttl_sec: float, max_entries: int):
        self.enabled = bool(enabled)
        self.ttl_sec = max(1.0, float(ttl_sec))
        self.max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        self._entries: dict[str, CacheEntry] = {}

    def get(self, key: str) -> ReputationAssessment | None:
        if not self.enabled:
            return None
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at < now:
                self._entries.pop(key, None)
                return None
            age_sec = int(max(0.0, now - entry.created_at))
            value = _clone_assessment(entry.value)
            value.provider_details = dict(value.provider_details)
            value.provider_details["cache"] = {"hit": True, "age_sec": age_sec}
            return value

    def set(self, key: str, value: ReputationAssessment) -> None:
        if not self.enabled:
            return
        now = time.time()
        with self._lock:
            if len(self._entries) >= self.max_entries:
                self._evict_oldest()
            self._entries[key] = CacheEntry(
                value=_clone_assessment(value),
                expires_at=now + self.ttl_sec,
                created_at=now,
            )

    def _evict_oldest(self) -> None:
        oldest_key: str | None = None
        oldest_time = float("inf")
        for key, entry in self._entries.items():
            if entry.created_at < oldest_time:
                oldest_key = key
                oldest_time = entry.created_at
        if oldest_key is not None:
            self._entries.pop(oldest_key, None)


def _clone_assessment(value: ReputationAssessment) -> ReputationAssessment:
    return ReputationAssessment(
        risk_delta=value.risk_delta,
        reasons=list(value.reasons),
        hard_block=value.hard_block,
        provider_details=dict(value.provider_details),
    )
