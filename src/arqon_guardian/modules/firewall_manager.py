from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import subprocess


LOGGER = logging.getLogger(__name__)


class FirewallManager:
    def __init__(self, state_dir: Path, rule_prefix: str):
        self.state_dir = state_dir
        self.rule_prefix = rule_prefix
        self.state_file = state_dir / "firewall-rules.json"
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def sync_blocked_hosts(self, hosts: list[str]) -> dict[str, int]:
        _ensure_windows()
        desired = {host.strip() for host in hosts if host.strip()}
        current = self._load_managed_hosts()

        to_remove = sorted(current - desired)
        to_add = sorted(desired - current)

        removed = 0
        added = 0

        for host in to_remove:
            if self._delete_rule_for_host(host):
                removed += 1

        for host in to_add:
            if self._add_rule_for_host(host):
                added += 1

        final_hosts = sorted((current - set(to_remove)) | set(to_add))
        self._save_managed_hosts(final_hosts)

        LOGGER.info("Firewall sync done: added=%s removed=%s total=%s", added, removed, len(final_hosts))
        return {"added": added, "removed": removed, "total": len(final_hosts)}

    def _rule_name(self, host: str) -> str:
        cleaned = host.replace("/", "_").replace(":", "_")
        return f"{self.rule_prefix}{cleaned}"

    def _add_rule_for_host(self, host: str) -> bool:
        rule_name = self._rule_name(host)
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={host}",
            "profile=any",
            "enable=yes",
        ]
        return _run_netsh(command)

    def _delete_rule_for_host(self, host: str) -> bool:
        rule_name = self._rule_name(host)
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
        return _run_netsh(command)

    def _load_managed_hosts(self) -> set[str]:
        if not self.state_file.exists():
            return set()
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return set()
        hosts = payload.get("hosts", [])
        if not isinstance(hosts, list):
            return set()
        return {str(host) for host in hosts}

    def _save_managed_hosts(self, hosts: list[str]) -> None:
        payload = {"hosts": hosts}
        self.state_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def _run_netsh(command: list[str]) -> bool:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        LOGGER.warning(
            "netsh command failed (code=%s): %s | stderr=%s",
            result.returncode,
            " ".join(command),
            result.stderr.strip(),
        )
        return False
    return True


def _ensure_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows firewall sync is supported only on Windows")

