from __future__ import annotations

import csv
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import logging
import mimetypes
from pathlib import Path
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from arqon_guardian.events import EventStore
from arqon_guardian.quarantine import QuarantineManager
from arqon_guardian.rules import Decision, RuleEvaluator


LOGGER = logging.getLogger(__name__)


class LocalApiServer:
    def __init__(
        self,
        evaluator: RuleEvaluator,
        quarantine: QuarantineManager,
        host: str,
        port: int,
        auth_key: str,
        admin_key: str,
        body_limit_bytes: int,
        rate_limit_enabled: bool = True,
        rate_limit_requests: int = 120,
        rate_limit_window_sec: float = 60.0,
        admin_rate_limit_requests: int = 80,
        event_store: EventStore | None = None,
        dashboard_dir: Path | None = None,
        status_provider: Callable[[], dict[str, Any]] | None = None,
        audit_tail_provider: Callable[[int], list[dict[str, Any]]] | None = None,
        self_check_provider: Callable[[bool], dict[str, Any]] | None = None,
    ):
        self.evaluator = evaluator
        self.quarantine = quarantine
        self.host = host
        self.port = int(port)
        self.auth_key = auth_key
        self.admin_key = admin_key or auth_key
        self.body_limit_bytes = max(1024, int(body_limit_bytes))
        self.rate_limiter = SlidingWindowRateLimiter(
            enabled=bool(rate_limit_enabled),
            user_limit=max(1, int(rate_limit_requests)),
            admin_limit=max(1, int(admin_rate_limit_requests)),
            window_sec=max(1.0, float(rate_limit_window_sec)),
        )
        self.event_store = event_store
        self.dashboard_dir = dashboard_dir
        self.status_provider = status_provider
        self.audit_tail_provider = audit_tail_provider
        self.self_check_provider = self_check_provider

        self._server = ThreadingHTTPServer((self.host, self.port), self._build_handler())
        bound_host, bound_port = self._server.server_address[0], self._server.server_address[1]
        self.host = str(bound_host)
        self.port = int(bound_port)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="arqon-local-api",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()
        LOGGER.info("Local API started at http://%s:%s", self.host, self.port)

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def join(self, timeout: float | None = None) -> None:
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)
        LOGGER.info("Local API stopped")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _build_handler(self):
        evaluator = self.evaluator
        quarantine = self.quarantine
        auth_key = self.auth_key
        admin_key = self.admin_key
        body_limit = self.body_limit_bytes
        rate_limiter = self.rate_limiter
        event_store = self.event_store
        dashboard_dir = self.dashboard_dir
        status_provider = self.status_provider
        audit_tail_provider = self.audit_tail_provider
        self_check_provider = self.self_check_provider

        class _Handler(BaseHTTPRequestHandler):
            server_version = "ARQONLocalAPI/0.2"

            def do_OPTIONS(self) -> None:
                self._write_json(HTTPStatus.NO_CONTENT, {})

            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                path = parsed.path
                params = parse_qs(parsed.query, keep_blank_values=False)

                if path == "/health":
                    payload = {"ok": True, "service": "arqon-local-api"}
                    if status_provider:
                        payload["runtime"] = status_provider()
                    self._write_json(HTTPStatus.OK, payload)
                    return

                if path in {"/", "/dashboard", "/dashboard/"}:
                    if not dashboard_dir:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "dashboard_not_configured"})
                        return
                    self._write_static_file(dashboard_dir / "index.html")
                    return

                if path.startswith("/dashboard/"):
                    if not dashboard_dir:
                        self._write_json(HTTPStatus.NOT_FOUND, {"error": "dashboard_not_configured"})
                        return
                    relative = path[len("/dashboard/") :].strip("/")
                    if not relative:
                        self._write_static_file(dashboard_dir / "index.html")
                        return
                    target = (dashboard_dir / relative).resolve()
                    if not _is_within_root(target, dashboard_dir):
                        self._write_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                        return
                    self._write_static_file(target)
                    return

                if path == "/v1/events":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    limit = _read_limit(params.get("limit", ["100"]))
                    payload = {"events": event_store.tail(limit=limit) if event_store else []}
                    self._write_json(HTTPStatus.OK, payload)
                    return

                if path == "/v1/incidents":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    limit = _read_limit(params.get("limit", ["1000"]))
                    min_level = _read_single(params.get("min_level", ["warning"]), default="warning")
                    incidents = (
                        event_store.incident_records(limit=limit, min_level=min_level)
                        if event_store
                        else []
                    )
                    payload = {
                        "count": len(incidents),
                        "min_level": min_level,
                        "incidents": incidents,
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return

                if path == "/v1/incidents/export":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    export_format = _read_single(params.get("format", ["json"]), default="json").lower()
                    if export_format not in {"json", "csv"}:
                        self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_export_format"})
                        return
                    limit = _read_limit(params.get("limit", ["1000"]))
                    min_level = _read_single(params.get("min_level", ["warning"]), default="warning")
                    incidents = (
                        event_store.incident_records(limit=limit, min_level=min_level)
                        if event_store
                        else []
                    )

                    if export_format == "json":
                        payload = {
                            "count": len(incidents),
                            "min_level": min_level,
                            "incidents": incidents,
                        }
                        self._write_json(HTTPStatus.OK, payload)
                        return

                    csv_payload = _incidents_to_csv(incidents)
                    self._write_text(
                        HTTPStatus.OK,
                        csv_payload,
                        content_type="text/csv; charset=utf-8",
                        filename="arqon-incidents.csv",
                    )
                    return

                if path == "/v1/quarantine":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    limit = _read_limit(params.get("limit", ["100"]))
                    payload = {"records": quarantine.tail_records(limit=limit)}
                    self._write_json(HTTPStatus.OK, payload)
                    return

                if path == "/v1/summary":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    event_summary = event_store.summary(limit=1000) if event_store else {"count": 0}
                    quarantine_count = len(quarantine.tail_records(limit=1000))
                    payload = {
                        "events": event_summary,
                        "quarantine_count": quarantine_count,
                        "api": {"host": self.server.server_address[0], "port": self.server.server_address[1]},
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return

                if path == "/v1/audit":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    limit = _read_limit(params.get("limit", ["100"]))
                    records = audit_tail_provider(limit) if audit_tail_provider else []
                    self._write_json(HTTPStatus.OK, {"records": records})
                    return

                if path == "/v1/self-check":
                    if not self._authorized_admin(user_key=auth_key, admin_key=admin_key):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "admin_unauthorized"})
                        return
                    if not self._consume_rate_limit(rate_limiter, scope="admin"):
                        return
                    skip_bind_check = _read_bool(params.get("skip_bind_check", ["true"]), default=True)
                    if self_check_provider:
                        payload = self_check_provider(skip_bind_check)
                    else:
                        payload = {"status": "not_available", "checks": []}
                    self._write_json(HTTPStatus.OK, payload)
                    return

                self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

            def do_POST(self) -> None:
                parsed = urlsplit(self.path)
                path = parsed.path

                if path not in {"/v1/url/evaluate", "/v1/file/evaluate"}:
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return

                if not self._authorized_user(auth_key):
                    self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                if not self._consume_rate_limit(rate_limiter, scope="user"):
                    return

                payload, error = self._read_json_body(body_limit)
                if error:
                    status = HTTPStatus.BAD_REQUEST
                    if error == "payload_too_large":
                        status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                    self._write_json(status, {"error": error})
                    return

                if path == "/v1/url/evaluate":
                    url = str(payload.get("url", "")).strip()
                    decision = evaluator.evaluate_url(url)
                    self._write_json(HTTPStatus.OK, _decision_payload(decision, {"url": url}))
                    return

                file_path = str(payload.get("path", "")).strip()
                quarantine_on_block = bool(payload.get("quarantine", False))
                if not file_path:
                    self._write_json(HTTPStatus.BAD_REQUEST, {"error": "path_required"})
                    return

                target = Path(file_path).expanduser().resolve()
                decision = evaluator.evaluate_file(target)
                response_payload = _decision_payload(decision, {"path": str(target)})

                if decision.should_block and quarantine_on_block:
                    quarantined_path = quarantine.quarantine_file(
                        target,
                        reason=",".join(decision.reasons),
                        sha256=decision.sha256,
                    )
                    response_payload["quarantined_path"] = (
                        str(quarantined_path) if quarantined_path else None
                    )

                self._write_json(HTTPStatus.OK, response_payload)

            def log_message(self, fmt: str, *args: Any) -> None:
                client_ip = self.client_address[0] if self.client_address else "unknown"
                LOGGER.debug("Local API %s - %s", client_ip, fmt % args)

            def _authorized_user(self, expected_key: str) -> bool:
                if not expected_key:
                    return True
                provided = self.headers.get("X-ARQON-Key", "")
                return hmac.compare_digest(provided, expected_key)

            def _authorized_admin(self, user_key: str, admin_key: str) -> bool:
                expected_admin = admin_key or user_key
                if not expected_admin:
                    return True
                provided_admin = self.headers.get("X-ARQON-Admin-Key", "")
                return hmac.compare_digest(provided_admin, expected_admin)

            def _consume_rate_limit(self, limiter: "SlidingWindowRateLimiter", scope: str) -> bool:
                client_ip = self.client_address[0] if self.client_address else "unknown"
                key = f"{scope}:{client_ip}:{self.path.split('?', 1)[0]}"
                if limiter.allow(key=key, scope=scope):
                    return True
                self._write_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "rate_limited", "scope": scope},
                )
                return False

            def _read_json_body(self, max_size: int) -> tuple[dict[str, Any], str | None]:
                content_length_raw = self.headers.get("Content-Length", "0")
                try:
                    content_length = int(content_length_raw)
                except ValueError:
                    return {}, "invalid_content_length"

                if content_length <= 0:
                    return {}, None
                if content_length > max_size:
                    return {}, "payload_too_large"

                raw = self.rfile.read(content_length)
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return {}, "invalid_json"
                if not isinstance(parsed, dict):
                    return {}, "invalid_json_object"
                return parsed, None

            def _write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
                self.send_response(status.value)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, X-ARQON-Key, X-ARQON-Admin-Key",
                )
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()
                if status != HTTPStatus.NO_CONTENT:
                    self.wfile.write(body)

            def _write_text(
                self,
                status: HTTPStatus,
                payload: str,
                *,
                content_type: str,
                filename: str | None = None,
            ) -> None:
                body = payload.encode("utf-8")
                self.send_response(status.value)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, X-ARQON-Key, X-ARQON-Admin-Key",
                )
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                if filename:
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.end_headers()
                if status != HTTPStatus.NO_CONTENT:
                    self.wfile.write(body)

            def _write_static_file(self, path: Path) -> None:
                if not path.exists() or not path.is_file():
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                raw = path.read_bytes()
                content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
                self.send_response(HTTPStatus.OK.value)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(raw)

        return _Handler


def _decision_payload(decision: Decision, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "action": decision.action,
        "risk_score": decision.risk_score,
        "reasons": decision.reasons,
        "sha256": decision.sha256,
        "details": decision.details,
    }
    if extra:
        payload.update(extra)
    return payload


def _read_limit(value: list[str]) -> int:
    if not value:
        return 100
    try:
        parsed = int(value[0])
    except (TypeError, ValueError):
        return 100
    return max(1, min(1000, parsed))


def _is_within_root(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _read_single(value: list[str], *, default: str) -> str:
    if not value:
        return default
    selected = str(value[0]).strip()
    return selected or default


def _read_bool(value: list[str], *, default: bool) -> bool:
    if not value:
        return default
    raw = str(value[0]).strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _incidents_to_csv(records: list[dict[str, Any]]) -> str:
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=["timestamp_utc", "type", "level", "message", "data_json"],
    )
    writer.writeheader()
    for record in records:
        writer.writerow(
            {
                "timestamp_utc": str(record.get("timestamp_utc", "")),
                "type": str(record.get("type", "")),
                "level": str(record.get("level", "")),
                "message": str(record.get("message", "")),
                "data_json": json.dumps(record.get("data", {}), ensure_ascii=True),
            }
        )
    return stream.getvalue()


class SlidingWindowRateLimiter:
    def __init__(
        self,
        *,
        enabled: bool,
        user_limit: int,
        admin_limit: int,
        window_sec: float,
    ):
        self.enabled = enabled
        self.user_limit = user_limit
        self.admin_limit = admin_limit
        self.window_sec = window_sec
        self._lock = threading.Lock()
        self._timestamps: dict[str, list[float]] = {}

    def allow(self, *, key: str, scope: str) -> bool:
        if not self.enabled:
            return True
        limit = self.admin_limit if scope == "admin" else self.user_limit
        now = time.time()
        cutoff = now - self.window_sec
        with self._lock:
            bucket = self._timestamps.get(key, [])
            bucket = [stamp for stamp in bucket if stamp >= cutoff]
            if len(bucket) >= limit:
                self._timestamps[key] = bucket
                return False
            bucket.append(now)
            self._timestamps[key] = bucket
            return True
