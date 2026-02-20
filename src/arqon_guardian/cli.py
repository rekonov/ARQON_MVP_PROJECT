from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path
from typing import Any

import yaml

from arqon_guardian.agent import SecurityAgent
from arqon_guardian.audit import AuditLogger
from arqon_guardian.config import load_config
from arqon_guardian.crypto_signing import generate_ed25519_keypair
from arqon_guardian.diagnostics import create_diagnostics_bundle
from arqon_guardian.events import EventStore
from arqon_guardian.health import health_exit_code, run_self_check
from arqon_guardian.logging_setup import configure_logging
from arqon_guardian.modules.firewall_manager import FirewallManager
from arqon_guardian.modules.local_api import LocalApiServer
from arqon_guardian.modules.network_privacy import ProxyManager
from arqon_guardian.modules.privacy_hardening import HardeningManager
from arqon_guardian.policy_pack import (
    PolicyPackError,
    apply_policy_pack,
    load_policy_pack,
    load_policy_source,
    pull_policy_pack,
    read_secrets,
    save_policy_pack,
    sign_policy_pack,
    verify_policy_pack,
)
from arqon_guardian.quarantine import QuarantineManager
from arqon_guardian.reputation import ReputationService
from arqon_guardian.retention import run_retention
from arqon_guardian.rules import RuleEvaluator
from arqon_guardian.runtime_lock import RuntimeLock, RuntimeLockError
from arqon_guardian.secret_store import SecretStore
from arqon_guardian.signature import SignatureInspector
from arqon_guardian.update_pack import (
    build_manifest,
    load_update_pack,
    save_update_pack,
    sign_update_pack,
    verify_update_pack,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ARQON Security Agent")
    parser.add_argument("--config", default=None, help="Path to YAML config file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Run realtime security agent")
    subparsers.add_parser("api-run", help="Run only local API server")

    self_check = subparsers.add_parser("self-check", help="Run local health checks for install/update")
    self_check.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero exit code for warnings",
    )
    self_check.add_argument(
        "--skip-bind-check",
        action="store_true",
        help="Skip API host/port bind check",
    )

    scan_file = subparsers.add_parser("scan-file", help="Evaluate one file against current rules")
    scan_file.add_argument("path", help="File path to scan")
    scan_file.add_argument("--quarantine", action="store_true", help="Quarantine file when blocked")

    scan_url = subparsers.add_parser("scan-url", help="Evaluate URL against phishing/malware rules")
    scan_url.add_argument("url", help="URL to evaluate")

    firewall_sync = subparsers.add_parser("firewall-sync", help="Sync Windows Firewall blocklist")
    firewall_sync.add_argument(
        "--hosts",
        nargs="*",
        default=None,
        help="Optional host list override; if omitted uses config.network.blocked_hosts",
    )

    privacy = subparsers.add_parser("privacy", help="Privacy hardening profiles")
    privacy_sub = privacy.add_subparsers(dest="privacy_command", required=True)
    privacy_sub.add_parser("list", help="List available hardening profiles")
    privacy_apply = privacy_sub.add_parser("apply", help="Apply hardening profile")
    privacy_apply.add_argument("profile", help="Profile name")
    privacy_rollback = privacy_sub.add_parser("rollback", help="Rollback using backup file")
    privacy_rollback.add_argument("--backup-file", default=None, help="Path to backup json")

    proxy = subparsers.add_parser("proxy", help="System proxy controls")
    proxy_sub = proxy.add_subparsers(dest="proxy_command", required=True)
    proxy_set = proxy_sub.add_parser("set", help="Enable proxy")
    proxy_set.add_argument("--host", required=True, help="Proxy host")
    proxy_set.add_argument("--port", required=True, type=int, help="Proxy port")
    proxy_sub.add_parser("disable", help="Disable proxy")
    proxy_sub.add_parser("status", help="Read current proxy status")

    policy = subparsers.add_parser("policy", help="Signed policy pack operations")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)

    policy_sign = policy_sub.add_parser("sign", help="Create signed policy pack")
    policy_sign.add_argument("--input", required=True, help="Policy source file (json/yaml)")
    policy_sign.add_argument("--output", required=True, help="Output pack file (json)")
    policy_sign.add_argument("--issuer", default="arqon-admin", help="Pack issuer")
    policy_sign.add_argument("--version", default=None, help="Pack version")
    policy_sign.add_argument("--notes", default=None, help="Optional pack notes")
    policy_sign.add_argument("--key-id", default="default", help="Signing key identifier")
    policy_sign.add_argument("--secret", default=None, help="Signing secret")
    policy_sign.add_argument("--secret-file", default=None, help="Path to secret file")
    policy_sign.add_argument("--keyring-file", default=None, help="Path to keyring file")

    policy_verify = policy_sub.add_parser("verify", help="Verify signed policy pack")
    policy_verify.add_argument("--pack", required=True, help="Pack file path")
    policy_verify.add_argument("--secret", default=None, help="Verification secret")
    policy_verify.add_argument("--secret-file", default=None, help="Path to secret file")
    policy_verify.add_argument("--keyring-file", default=None, help="Path to keyring file")

    policy_apply = policy_sub.add_parser("apply", help="Apply signed policy pack to config")
    policy_apply.add_argument("--pack", required=True, help="Pack file path")
    policy_apply.add_argument("--secret", default=None, help="Verification secret")
    policy_apply.add_argument("--secret-file", default=None, help="Path to secret file")
    policy_apply.add_argument("--keyring-file", default=None, help="Path to keyring file")
    policy_apply.add_argument("--allow-replay", action="store_true", help="Allow same/older version")

    policy_pull = policy_sub.add_parser("pull", help="Download and apply signed policy pack")
    policy_pull.add_argument("--url", required=True, help="Pack URL")
    policy_pull.add_argument("--secret", default=None, help="Verification secret")
    policy_pull.add_argument("--secret-file", default=None, help="Path to secret file")
    policy_pull.add_argument("--keyring-file", default=None, help="Path to keyring file")
    policy_pull.add_argument("--allow-replay", action="store_true", help="Allow same/older version")
    policy_pull.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout seconds")

    incidents = subparsers.add_parser("incidents", help="Incident records operations")
    incidents_sub = incidents.add_subparsers(dest="incidents_command", required=True)
    incidents_export = incidents_sub.add_parser("export", help="Export incidents from local event store")
    incidents_export.add_argument(
        "--format",
        default="json",
        choices=["json", "csv"],
        help="Export format",
    )
    incidents_export.add_argument("--output", required=True, help="Output file path")
    incidents_export.add_argument("--limit", type=int, default=1000, help="Max incidents to export")
    incidents_export.add_argument(
        "--min-level",
        default="warning",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Minimum severity level",
    )

    diagnostics = subparsers.add_parser("diagnostics", help="Diagnostics bundle operations")
    diagnostics_sub = diagnostics.add_subparsers(dest="diagnostics_command", required=True)
    diagnostics_bundle = diagnostics_sub.add_parser("bundle", help="Create diagnostics ZIP bundle")
    diagnostics_bundle.add_argument(
        "--output",
        default=None,
        help="Output ZIP path (default: state/diagnostics-<timestamp>.zip)",
    )
    diagnostics_bundle.add_argument("--events-limit", type=int, default=1000, help="Events tail limit")
    diagnostics_bundle.add_argument("--audit-limit", type=int, default=1000, help="Audit tail limit")
    diagnostics_bundle.add_argument(
        "--quarantine-limit",
        type=int,
        default=500,
        help="Quarantine records limit",
    )
    diagnostics_bundle.add_argument(
        "--include-bind-check",
        action="store_true",
        help="Include API bind check in self-check snapshot",
    )

    config_cmd = subparsers.add_parser("config", help="Configuration utility commands")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    rotate_keys = config_sub.add_parser("rotate-keys", help="Generate and persist new API keys")
    rotate_keys.add_argument("--user-key", default=None, help="Explicit user key value")
    rotate_keys.add_argument("--admin-key", default=None, help="Explicit admin key value")
    rotate_keys.add_argument("--length", type=int, default=32, help="Random key length when auto-generating")
    rotate_keys.add_argument(
        "--store-file",
        default=None,
        help="Override secret store file path",
    )
    rotate_keys.add_argument(
        "--config-mode",
        choices=["refs", "plaintext"],
        default="refs",
        help="Persist API keys as secret refs (recommended) or plaintext in config",
    )
    rotate_keys.add_argument(
        "--print-only",
        action="store_true",
        help="Only print generated keys without writing config file",
    )

    ensure_keys = config_sub.add_parser(
        "ensure-keys",
        help="Ensure API keys exist in secret store/config without rotating existing values",
    )
    ensure_keys.add_argument("--length", type=int, default=32, help="Generated key length for missing keys")
    ensure_keys.add_argument("--store-file", default=None, help="Override secret store file path")
    ensure_keys.add_argument(
        "--config-mode",
        choices=["refs", "plaintext"],
        default="refs",
        help="Persist API keys as secret refs (recommended) or plaintext",
    )

    secret_store_cmd = config_sub.add_parser("secret-store", help="Manage secure secret store")
    secret_store_sub = secret_store_cmd.add_subparsers(dest="secret_store_command", required=True)
    secret_store_set = secret_store_sub.add_parser("set", help="Set secret in store")
    secret_store_set.add_argument("--name", required=True, help="Secret name")
    secret_store_set.add_argument("--value", required=True, help="Secret value")
    secret_store_set.add_argument("--store-file", default=None, help="Override store file path")
    secret_store_get = secret_store_sub.add_parser("get", help="Get secret from store")
    secret_store_get.add_argument("--name", required=True, help="Secret name")
    secret_store_get.add_argument("--store-file", default=None, help="Override store file path")
    secret_store_get.add_argument("--masked", action="store_true", help="Mask value in output")
    secret_store_list = secret_store_sub.add_parser("list", help="List secret keys")
    secret_store_list.add_argument("--store-file", default=None, help="Override store file path")

    crypto_cmd = subparsers.add_parser("crypto", help="Cryptographic helpers")
    crypto_sub = crypto_cmd.add_subparsers(dest="crypto_command", required=True)
    keygen = crypto_sub.add_parser("keygen", help="Generate Ed25519 keypair")
    keygen.add_argument("--private-out", required=True, help="Private key PEM output path")
    keygen.add_argument("--public-out", required=True, help="Public key PEM output path")
    keygen.add_argument("--key-id", default="default", help="Key identifier for keyring output")
    keygen.add_argument(
        "--keyring-out",
        default=None,
        help="Optional JSON keyring output file with public key",
    )

    maintenance_cmd = subparsers.add_parser("maintenance", help="Maintenance operations")
    maintenance_sub = maintenance_cmd.add_subparsers(dest="maintenance_command", required=True)
    maintenance_cleanup = maintenance_sub.add_parser("cleanup", help="Run retention cleanup once")
    maintenance_cleanup.add_argument(
        "--print-config",
        action="store_true",
        help="Print active retention config before cleanup",
    )

    update_pack = subparsers.add_parser("update-pack", help="Signed update package operations")
    update_pack_sub = update_pack.add_subparsers(dest="update_pack_command", required=True)

    update_pack_build = update_pack_sub.add_parser("build", help="Build and sign update package manifest")
    update_pack_build.add_argument("--source-root", required=True, help="Project/source root to package")
    update_pack_build.add_argument("--output", required=True, help="Output update pack file")
    update_pack_build.add_argument("--issuer", default="arqon-release", help="Update pack issuer")
    update_pack_build.add_argument("--version", default=None, help="Pack version")
    update_pack_build.add_argument("--notes", default=None, help="Optional pack notes")
    update_pack_build.add_argument("--key-id", default="default", help="Signing key identifier")
    update_pack_build.add_argument("--secret", default=None, help="Signing secret")
    update_pack_build.add_argument("--secret-file", default=None, help="Path to secret file")
    update_pack_build.add_argument("--keyring-file", default=None, help="Path to keyring file")
    update_pack_build.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Optional artifact root/file (repeatable)",
    )

    update_pack_verify = update_pack_sub.add_parser("verify", help="Verify signed update package")
    update_pack_verify.add_argument("--pack", required=True, help="Update pack file")
    update_pack_verify.add_argument("--source-root", required=True, help="Root folder to verify against")
    update_pack_verify.add_argument("--secret", default=None, help="Verification secret")
    update_pack_verify.add_argument("--secret-file", default=None, help="Path to secret file")
    update_pack_verify.add_argument("--keyring-file", default=None, help="Path to keyring file")
    update_pack_verify.add_argument(
        "--allow-extra-files",
        action="store_true",
        help="Allow extra files under artifact roots",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        configure_logging(config.log_file, verbose=args.verbose)
        if args.command == "self-check":
            return _handle_self_check(config, args)

        evaluator = _build_evaluator(config)
        audit_logger = AuditLogger(config.state_dir)

        if args.command == "run":
            lock = RuntimeLock(config.state_dir / "arqon-runtime.lock")
            try:
                lock.acquire()
            except RuntimeLockError as error:
                _print_json({"error": "runtime_already_running", "details": str(error)})
                return 12
            try:
                agent = SecurityAgent(config)
                agent.run_forever()
                return 0
            finally:
                lock.release()

        if args.command == "api-run":
            lock = RuntimeLock(config.state_dir / "arqon-runtime.lock")
            try:
                lock.acquire()
            except RuntimeLockError as error:
                _print_json({"error": "runtime_already_running", "details": str(error)})
                return 12
            try:
                return _handle_api_run(config, evaluator, audit_logger)
            finally:
                lock.release()

        if args.command == "scan-file":
            return _handle_scan_file(config, evaluator, args.path, args.quarantine)

        if args.command == "scan-url":
            return _handle_scan_url(evaluator, args.url)

        if args.command == "firewall-sync":
            return _handle_firewall_sync(config, args.hosts, audit_logger)

        if args.command == "privacy":
            return _handle_privacy(config, args, audit_logger)

        if args.command == "proxy":
            return _handle_proxy(args, audit_logger)

        if args.command == "policy":
            return _handle_policy(config, args, audit_logger)

        if args.command == "incidents":
            return _handle_incidents(config, args, audit_logger)

        if args.command == "update-pack":
            return _handle_update_pack(config, args, audit_logger)

        if args.command == "diagnostics":
            return _handle_diagnostics(config, args, audit_logger)

        if args.command == "config":
            return _handle_config_command(config, args, audit_logger)

        if args.command == "crypto":
            return _handle_crypto_command(args)

        if args.command == "maintenance":
            return _handle_maintenance(config, args, audit_logger)

        parser.error(f"Unknown command: {args.command}")
        return 2
    except Exception as error:
        _print_json({"error": str(error), "type": error.__class__.__name__})
        return 1


def _build_evaluator(config) -> RuleEvaluator:
    reputation = ReputationService(config.reputation_config)
    signature = SignatureInspector()
    return RuleEvaluator(
        config.rules,
        risk_config=config.risk_config,
        reputation_service=reputation,
        signature_inspector=signature,
    )


def _handle_scan_file(config, evaluator: RuleEvaluator, file_path: str, quarantine_on_block: bool) -> int:
    target = Path(file_path).expanduser().resolve()
    decision = evaluator.evaluate_file(target)

    result: dict[str, Any] = {
        "path": str(target),
        "action": decision.action,
        "risk_score": decision.risk_score,
        "reasons": decision.reasons,
        "sha256": decision.sha256,
        "details": decision.details,
    }

    if decision.should_block and quarantine_on_block:
        quarantine = QuarantineManager(config.quarantine_dir, config.state_dir)
        quarantined_path = quarantine.quarantine_file(
            target, reason=",".join(decision.reasons), sha256=decision.sha256
        )
        result["quarantined_path"] = str(quarantined_path) if quarantined_path else None

    _print_json(result)
    return _exit_code_for_decision(decision.action)


def _handle_scan_url(evaluator: RuleEvaluator, url: str) -> int:
    decision = evaluator.evaluate_url(url)
    result = {
        "url": url,
        "action": decision.action,
        "risk_score": decision.risk_score,
        "reasons": decision.reasons,
        "details": decision.details,
    }
    _print_json(result)
    return _exit_code_for_decision(decision.action)


def _handle_api_run(config, evaluator: RuleEvaluator, audit_logger: AuditLogger) -> int:
    api_cfg = config.api_config
    event_store = EventStore(config.state_dir)
    server = LocalApiServer(
        evaluator=evaluator,
        quarantine=QuarantineManager(config.quarantine_dir, config.state_dir),
        host=str(api_cfg.get("host", "127.0.0.1")),
        port=int(api_cfg.get("port", 8765)),
        auth_key=str(api_cfg.get("auth_key", "")),
        admin_key=str(api_cfg.get("admin_key", "")),
        body_limit_bytes=int(api_cfg.get("body_limit_bytes", 65536)),
        rate_limit_enabled=bool(api_cfg.get("rate_limit_enabled", True)),
        rate_limit_requests=int(api_cfg.get("rate_limit_requests", 120)),
        rate_limit_window_sec=float(api_cfg.get("rate_limit_window_sec", 60)),
        admin_rate_limit_requests=int(api_cfg.get("admin_rate_limit_requests", 80)),
        event_store=event_store,
        dashboard_dir=config.project_root / "dashboard",
        status_provider=lambda: {"running": True, "modules": ["LocalApiServer"], "uptime_sec": 0},
        audit_tail_provider=audit_logger.tail,
        self_check_provider=lambda skip_bind_check: run_self_check(
            config, check_bind=not bool(skip_bind_check)
        ),
    )
    server.start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        server.join(timeout=3.0)
    return 0


def _handle_firewall_sync(
    config,
    override_hosts: list[str] | None,
    audit_logger: AuditLogger,
) -> int:
    manager = FirewallManager(config.state_dir, config.firewall_rule_prefix)
    hosts = override_hosts if override_hosts is not None else config.blocked_hosts
    try:
        result = manager.sync_blocked_hosts(hosts)
        audit_logger.log(
            action="firewall_sync",
            status="success",
            actor="cli",
            source="cli",
            details={"hosts": hosts, "result": result},
        )
        _print_json(result)
        return 0
    except Exception as error:
        audit_logger.log(
            action="firewall_sync",
            status="failed",
            actor="cli",
            source="cli",
            details={"hosts": hosts, "error": str(error)},
        )
        raise


def _handle_privacy(config, args, audit_logger: AuditLogger) -> int:
    manager = HardeningManager(config.state_dir)

    if args.privacy_command == "list":
        result = {"profiles": manager.list_profiles()}
        _print_json(result)
        return 0

    if args.privacy_command == "apply":
        try:
            result = manager.apply_profile(args.profile)
            audit_logger.log(
                action="privacy_apply",
                status="success",
                actor="cli",
                source="cli",
                details={"profile": args.profile, "result": result},
            )
            _print_json(result)
            return 0
        except Exception as error:
            audit_logger.log(
                action="privacy_apply",
                status="failed",
                actor="cli",
                source="cli",
                details={"profile": args.profile, "error": str(error)},
            )
            raise

    if args.privacy_command == "rollback":
        backup = Path(args.backup_file).resolve() if args.backup_file else None
        try:
            result = manager.rollback(backup)
            audit_logger.log(
                action="privacy_rollback",
                status="success",
                actor="cli",
                source="cli",
                details={"backup_file": str(backup) if backup else None, "result": result},
            )
            _print_json(result)
            return 0
        except Exception as error:
            audit_logger.log(
                action="privacy_rollback",
                status="failed",
                actor="cli",
                source="cli",
                details={"backup_file": str(backup) if backup else None, "error": str(error)},
            )
            raise

    raise ValueError(f"Unknown privacy subcommand: {args.privacy_command}")


def _handle_proxy(args, audit_logger: AuditLogger) -> int:
    manager = ProxyManager()

    if args.proxy_command == "set":
        try:
            result = manager.enable_proxy(args.host, int(args.port))
            audit_logger.log(
                action="proxy_set",
                status="success",
                actor="cli",
                source="cli",
                details={"host": args.host, "port": int(args.port), "result": result},
            )
            _print_json(result)
            return 0
        except Exception as error:
            audit_logger.log(
                action="proxy_set",
                status="failed",
                actor="cli",
                source="cli",
                details={"host": args.host, "port": int(args.port), "error": str(error)},
            )
            raise

    if args.proxy_command == "disable":
        try:
            result = manager.disable_proxy()
            audit_logger.log(
                action="proxy_disable",
                status="success",
                actor="cli",
                source="cli",
                details={"result": result},
            )
            _print_json(result)
            return 0
        except Exception as error:
            audit_logger.log(
                action="proxy_disable",
                status="failed",
                actor="cli",
                source="cli",
                details={"error": str(error)},
            )
            raise

    if args.proxy_command == "status":
        result = manager.status()
        _print_json(result)
        return 0

    raise ValueError(f"Unknown proxy subcommand: {args.proxy_command}")


def _handle_policy(config, args, audit_logger: AuditLogger) -> int:
    default_secret_file = _resolve_default_secret_file(config)
    default_keyring_file = _resolve_default_keyring_file(config)

    if args.policy_command == "sign":
        source = load_policy_source(Path(args.input).resolve())
        secrets = read_secrets(
            secret=args.secret,
            secret_file=_pick_secret_file(args.secret_file, default_secret_file),
            keyring_file=_pick_keyring_file(args.keyring_file, default_keyring_file),
        )
        selected_secret = _select_signing_secret(secrets, args.key_id)
        pack = sign_policy_pack(
            policy_data=source,
            secret=selected_secret,
            issuer=args.issuer,
            version=args.version,
            notes=args.notes,
            key_id=args.key_id,
        )
        output_path = Path(args.output).resolve()
        save_policy_pack(pack, output_path)
        audit_logger.log(
            action="policy_sign",
            status="success",
            actor="cli",
            source="cli",
            details={"output": str(output_path), "meta": pack["meta"], "key_id": args.key_id},
        )
        _print_json({"created": True, "output": str(output_path), "meta": pack["meta"]})
        return 0

    if args.policy_command == "verify":
        pack = load_policy_pack(Path(args.pack).resolve())
        secrets = read_secrets(
            secret=args.secret,
            secret_file=_pick_secret_file(args.secret_file, default_secret_file),
            keyring_file=_pick_keyring_file(args.keyring_file, default_keyring_file),
        )
        ok, reason = verify_policy_pack(pack, secrets)
        _print_json({"valid": ok, "reason": reason, "meta": pack.get("meta", {})})
        return 0 if ok else 10

    if args.policy_command == "apply":
        pack = load_policy_pack(Path(args.pack).resolve())
        secrets = read_secrets(
            secret=args.secret,
            secret_file=_pick_secret_file(args.secret_file, default_secret_file),
            keyring_file=_pick_keyring_file(args.keyring_file, default_keyring_file),
        )
        try:
            result = apply_policy_pack(
                pack=pack,
                config_path=config.config_path,
                secrets=secrets,
                state_dir=config.state_dir,
                enforce_monotonic_version=True,
                allow_replay=bool(args.allow_replay),
            )
            audit_logger.log(
                action="policy_apply",
                status="success",
                actor="cli",
                source="cli",
                details={"pack": str(Path(args.pack).resolve()), "result": result},
            )
            _print_json(result)
            return 0
        except Exception as error:
            audit_logger.log(
                action="policy_apply",
                status="failed",
                actor="cli",
                source="cli",
                details={"pack": str(Path(args.pack).resolve()), "error": str(error)},
            )
            raise

    if args.policy_command == "pull":
        secrets = read_secrets(
            secret=args.secret,
            secret_file=_pick_secret_file(args.secret_file, default_secret_file),
            keyring_file=_pick_keyring_file(args.keyring_file, default_keyring_file),
        )
        pack = pull_policy_pack(args.url, timeout_sec=float(args.timeout))
        try:
            result = apply_policy_pack(
                pack=pack,
                config_path=config.config_path,
                secrets=secrets,
                state_dir=config.state_dir,
                enforce_monotonic_version=True,
                allow_replay=bool(args.allow_replay),
            )
            audit_logger.log(
                action="policy_pull_apply",
                status="success",
                actor="cli",
                source="cli",
                details={"url": args.url, "result": result},
            )
            _print_json(result)
            return 0
        except Exception as error:
            audit_logger.log(
                action="policy_pull_apply",
                status="failed",
                actor="cli",
                source="cli",
                details={"url": args.url, "error": str(error)},
            )
            raise

    raise PolicyPackError(f"Unknown policy subcommand: {args.policy_command}")


def _handle_incidents(config, args, audit_logger: AuditLogger) -> int:
    store = EventStore(config.state_dir)

    if args.incidents_command == "export":
        output_path = Path(args.output).expanduser().resolve()
        result = store.export_incidents(
            output_path=output_path,
            export_format=str(args.format),
            limit=int(args.limit),
            min_level=str(args.min_level),
        )
        audit_logger.log(
            action="incidents_export",
            status="success",
            actor="cli",
            source="cli",
            details=result,
        )
        _print_json(result)
        return 0

    raise ValueError(f"Unknown incidents subcommand: {args.incidents_command}")


def _handle_self_check(config, args) -> int:
    payload = run_self_check(config, check_bind=not bool(args.skip_bind_check))
    _print_json(payload)
    return health_exit_code(payload, strict=bool(args.strict))


def _handle_update_pack(config, args, audit_logger: AuditLogger) -> int:
    default_secret_file = _resolve_default_secret_file(config)
    default_keyring_file = _resolve_default_keyring_file(config)

    if args.update_pack_command == "build":
        source_root = Path(args.source_root).expanduser().resolve()
        artifacts: list[str] | None = None
        if args.artifact:
            artifacts = [str(item) for item in args.artifact if str(item).strip()]
        manifest = build_manifest(source_root=source_root, artifacts=artifacts)
        secrets = read_secrets(
            secret=args.secret,
            secret_file=_pick_secret_file(args.secret_file, default_secret_file),
            keyring_file=_pick_keyring_file(args.keyring_file, default_keyring_file),
        )
        selected_secret = _select_signing_secret(secrets, args.key_id)
        pack = sign_update_pack(
            manifest=manifest,
            secret=selected_secret,
            issuer=args.issuer,
            version=args.version,
            notes=args.notes,
            key_id=args.key_id,
        )
        output_path = Path(args.output).expanduser().resolve()
        save_update_pack(pack, output_path)
        result = {
            "created": True,
            "output": str(output_path),
            "meta": pack.get("meta", {}),
            "manifest": {
                "file_count": manifest.get("file_count", 0),
                "total_size_bytes": manifest.get("total_size_bytes", 0),
                "missing_artifacts": manifest.get("missing_artifacts", []),
            },
        }
        audit_logger.log(
            action="update_pack_build",
            status="success",
            actor="cli",
            source="cli",
            details=result,
        )
        _print_json(result)
        return 0

    if args.update_pack_command == "verify":
        pack = load_update_pack(Path(args.pack).expanduser().resolve())
        secrets = read_secrets(
            secret=args.secret,
            secret_file=_pick_secret_file(args.secret_file, default_secret_file),
            keyring_file=_pick_keyring_file(args.keyring_file, default_keyring_file),
        )
        ok, reason, details = verify_update_pack(
            pack,
            source_root=Path(args.source_root).expanduser().resolve(),
            secrets=secrets,
            strict_tree=not bool(args.allow_extra_files),
        )
        payload = {"valid": ok, "reason": reason, "details": details, "meta": pack.get("meta", {})}
        _print_json(payload)
        audit_logger.log(
            action="update_pack_verify",
            status="success" if ok else "failed",
            actor="cli",
            source="cli",
            details=payload,
        )
        return 0 if ok else 10

    raise ValueError(f"Unknown update-pack subcommand: {args.update_pack_command}")


def _handle_diagnostics(config, args, audit_logger: AuditLogger) -> int:
    if args.diagnostics_command != "bundle":
        raise ValueError(f"Unknown diagnostics subcommand: {args.diagnostics_command}")

    event_store = EventStore(config.state_dir)
    quarantine = QuarantineManager(config.quarantine_dir, config.state_dir)

    output_path: Path
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
    else:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_path = (config.state_dir / f"diagnostics-{timestamp}.zip").resolve()

    result = create_diagnostics_bundle(
        config=config,
        event_store=event_store,
        audit_logger=audit_logger,
        quarantine=quarantine,
        output_path=output_path,
        events_limit=int(args.events_limit),
        audit_limit=int(args.audit_limit),
        quarantine_limit=int(args.quarantine_limit),
        include_bind_check=bool(args.include_bind_check),
    )
    audit_logger.log(
        action="diagnostics_bundle",
        status="success",
        actor="cli",
        source="cli",
        details=result,
    )
    _print_json(result)
    return 0


def _handle_config_command(config, args, audit_logger: AuditLogger) -> int:
    if args.config_command == "rotate-keys":
        length = max(16, min(256, int(args.length)))
        user_key = str(args.user_key).strip() if args.user_key else _generate_key(length)
        admin_key = str(args.admin_key).strip() if args.admin_key else _generate_key(length)
        if not user_key or not admin_key:
            raise ValueError("Generated keys cannot be empty")

        store_file = _resolve_store_file(config, args.store_file)
        config_mode = str(args.config_mode).strip().lower()
        if config_mode not in {"refs", "plaintext"}:
            raise ValueError("config_mode must be refs or plaintext")

        result = {
            "config_path": str(config.config_path),
            "store_file": str(store_file),
            "config_mode": config_mode,
            "user_key": user_key,
            "admin_key": admin_key,
            "written": False,
        }

        if not bool(args.print_only):
            if config_mode == "refs":
                store = SecretStore(store_file)
                store.ensure()
                store.set("api_user_key", user_key)
                store.set("api_admin_key", admin_key)
                _write_rotated_keys_refs(
                    config.config_path,
                    user_ref="api_user_key",
                    admin_ref="api_admin_key",
                )
            else:
                _write_rotated_keys_plaintext(config.config_path, user_key=user_key, admin_key=admin_key)
            result["written"] = True
            audit_logger.log(
                action="config_rotate_keys",
                status="success",
                actor="cli",
                source="cli",
                details={
                    "config_path": str(config.config_path),
                    "store_file": str(store_file),
                    "config_mode": config_mode,
                },
            )
        _print_json(result)
        return 0

    if args.config_command == "ensure-keys":
        length = max(16, min(256, int(args.length)))
        store_file = _resolve_store_file(config, args.store_file)
        config_mode = str(args.config_mode).strip().lower()
        store = SecretStore(store_file)
        store.ensure()

        user_key = store.get("api_user_key")
        admin_key = store.get("api_admin_key")
        created: list[str] = []
        if not user_key:
            user_key = _generate_key(length)
            store.set("api_user_key", user_key)
            created.append("api_user_key")
        if not admin_key:
            admin_key = _generate_key(length)
            store.set("api_admin_key", admin_key)
            created.append("api_admin_key")

        if config_mode == "refs":
            _write_rotated_keys_refs(
                config.config_path,
                user_ref="api_user_key",
                admin_ref="api_admin_key",
            )
        else:
            _write_rotated_keys_plaintext(config.config_path, user_key=user_key, admin_key=admin_key)

        payload = {
            "config_path": str(config.config_path),
            "store_file": str(store_file),
            "config_mode": config_mode,
            "created": created,
            "created_count": len(created),
            "existing": [name for name in ("api_user_key", "api_admin_key") if name not in created],
        }
        audit_logger.log(
            action="config_ensure_keys",
            status="success",
            actor="cli",
            source="cli",
            details=payload,
        )
        _print_json(payload)
        return 0

    if args.config_command == "secret-store":
        store_file = _resolve_store_file(config, getattr(args, "store_file", None))
        store = SecretStore(store_file)
        if args.secret_store_command == "set":
            store.set(str(args.name), str(args.value))
            payload = {"store_file": str(store_file), "set": True, "name": str(args.name)}
            _print_json(payload)
            return 0
        if args.secret_store_command == "get":
            value = store.get(str(args.name))
            masked = bool(args.masked)
            shown = None if value is None else ("***masked***" if masked else value)
            _print_json({"store_file": str(store_file), "name": str(args.name), "value": shown, "found": value is not None})
            return 0
        if args.secret_store_command == "list":
            _print_json({"store_file": str(store_file), "keys": store.list_keys()})
            return 0
        raise ValueError(f"Unknown secret-store subcommand: {args.secret_store_command}")

    raise ValueError(f"Unknown config subcommand: {args.config_command}")


def _handle_crypto_command(args) -> int:
    if args.crypto_command != "keygen":
        raise ValueError(f"Unknown crypto subcommand: {args.crypto_command}")
    pair = generate_ed25519_keypair()
    private_out = Path(args.private_out).expanduser().resolve()
    public_out = Path(args.public_out).expanduser().resolve()
    private_out.parent.mkdir(parents=True, exist_ok=True)
    public_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_text(pair.private_key_pem, encoding="utf-8")
    public_out.write_text(pair.public_key_pem, encoding="utf-8")

    payload: dict[str, Any] = {
        "created": True,
        "private_out": str(private_out),
        "public_out": str(public_out),
    }

    keyring_out = str(args.keyring_out or "").strip()
    if keyring_out:
        keyring_path = Path(keyring_out).expanduser().resolve()
        keyring_path.parent.mkdir(parents=True, exist_ok=True)
        key_id = str(args.key_id or "default").strip() or "default"
        keyring_payload = {"keys": {key_id: {"public_key_pem": pair.public_key_pem}}}
        keyring_path.write_text(json.dumps(keyring_payload, ensure_ascii=True, indent=2), encoding="utf-8")
        payload["keyring_out"] = str(keyring_path)
        payload["key_id"] = key_id

    _print_json(payload)
    return 0


def _handle_maintenance(config, args, audit_logger: AuditLogger) -> int:
    if args.maintenance_command != "cleanup":
        raise ValueError(f"Unknown maintenance subcommand: {args.maintenance_command}")

    retention_cfg = config.retention_config
    if bool(args.print_config):
        _print_json({"retention_config": retention_cfg})

    result = run_retention(
        state_dir=config.state_dir,
        quarantine_dir=config.quarantine_dir,
        project_root=config.project_root,
        config=retention_cfg,
    )
    audit_logger.log(
        action="maintenance_cleanup",
        status="success",
        actor="cli",
        source="cli",
        details=result,
    )
    _print_json(result)
    return 0


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=True, indent=2))


def _exit_code_for_decision(action: str) -> int:
    if action == "allow":
        return 0
    if action == "warn":
        return 5
    return 10


def _resolve_default_secret_file(config) -> Path | None:
    raw = str(
        config.policy_updates_config.get("private_key_file")
        or config.policy_updates_config.get("secret_file", "")
    ).strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = (config.path_base_dir / path).resolve()
    return path


def _pick_secret_file(cli_value: str | None, default_path: Path | None) -> Path | None:
    if cli_value:
        return Path(cli_value).resolve()
    return default_path


def _resolve_default_keyring_file(config) -> Path | None:
    raw = str(
        config.policy_updates_config.get("public_keyring_file")
        or config.policy_updates_config.get("keyring_file", "")
    ).strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = (config.path_base_dir / path).resolve()
    return path


def _pick_keyring_file(cli_value: str | None, default_path: Path | None) -> Path | None:
    if cli_value:
        return Path(cli_value).resolve()
    return default_path


def _select_signing_secret(secrets: dict[str, str], key_id: str) -> str:
    normalized = key_id.strip() or "default"
    selected = secrets.get(normalized)
    if selected:
        return selected
    if normalized == "default" and len(secrets) == 1:
        return next(iter(secrets.values()))
    raise PolicyPackError(f"Secret for key_id not found: {normalized}")


def _generate_key(length: int) -> str:
    token = secrets.token_urlsafe(length)
    return token[:length]


def _write_rotated_keys_plaintext(config_path: Path, *, user_key: str, admin_key: str) -> None:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be object: {config_path}")

    api_section = raw.get("api")
    if not isinstance(api_section, dict):
        api_section = {}
        raw["api"] = api_section

    api_section["auth_key"] = user_key
    api_section["admin_key"] = admin_key
    api_section["auth_key_ref"] = ""
    api_section["admin_key_ref"] = ""
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _write_rotated_keys_refs(config_path: Path, *, user_ref: str, admin_ref: str) -> None:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"Config root must be object: {config_path}")

    api_section = raw.get("api")
    if not isinstance(api_section, dict):
        api_section = {}
        raw["api"] = api_section

    api_section["auth_key"] = ""
    api_section["admin_key"] = ""
    api_section["auth_key_ref"] = user_ref
    api_section["admin_key_ref"] = admin_ref
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _resolve_store_file(config, override: str | None) -> Path:
    if override and str(override).strip():
        return Path(override).expanduser().resolve()
    return config.secret_store_file.resolve()


if __name__ == "__main__":
    raise SystemExit(main())
