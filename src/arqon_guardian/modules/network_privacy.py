from __future__ import annotations

import logging
import os
import subprocess
from typing import Any

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None


LOGGER = logging.getLogger(__name__)


class ProxyManager:
    INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def enable_proxy(self, host: str, port: int) -> dict[str, Any]:
        _ensure_windows()
        if not host.strip():
            raise ValueError("Proxy host cannot be empty")
        if port < 1 or port > 65535:
            raise ValueError("Proxy port must be within 1..65535")

        server = f"{host}:{port}"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)

        _run_command(["netsh", "winhttp", "set", "proxy", server])
        LOGGER.info("System proxy enabled: %s", server)
        return {"enabled": True, "server": server}

    def disable_proxy(self) -> dict[str, Any]:
        _ensure_windows()
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(key, "ProxyServer")
            except FileNotFoundError:
                pass

        _run_command(["netsh", "winhttp", "reset", "proxy"])
        LOGGER.info("System proxy disabled")
        return {"enabled": False}

    def status(self) -> dict[str, Any]:
        _ensure_windows()
        enabled = 0
        server = ""
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                enabled = 0
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                server = ""

        return {"enabled": bool(enabled), "server": server}


def _run_command(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        LOGGER.warning(
            "Command failed (code=%s): %s | stderr=%s",
            result.returncode,
            " ".join(command),
            result.stderr.strip(),
        )


def _ensure_windows() -> None:
    if os.name != "nt" or winreg is None:
        raise RuntimeError("Proxy controls are supported only on Windows")

