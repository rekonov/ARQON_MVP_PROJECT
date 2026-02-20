from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import subprocess


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SignatureInfo:
    status: str
    signer: str | None
    is_signed: bool
    is_trusted: bool
    error: str | None = None


class SignatureInspector:
    inspectable_extensions = {
        ".exe",
        ".dll",
        ".msi",
        ".sys",
        ".ocx",
        ".ps1",
        ".psm1",
        ".vbs",
        ".js",
        ".cmd",
        ".bat",
    }

    def inspect(self, path: Path) -> SignatureInfo:
        ext = path.suffix.lower()
        if ext not in self.inspectable_extensions:
            return SignatureInfo(
                status="Skipped",
                signer=None,
                is_signed=False,
                is_trusted=False,
                error="unsupported_extension",
            )
        if os.name != "nt":
            return SignatureInfo(
                status="UnsupportedOS",
                signer=None,
                is_signed=False,
                is_trusted=False,
                error="non_windows",
            )

        powershell_path = _resolve_powershell()
        escaped_path = str(path).replace("'", "''")
        command = (
            "$sig = Get-AuthenticodeSignature -FilePath "
            f"'{escaped_path}'; "
            "$signer=''; if ($sig.SignerCertificate) { $signer=$sig.SignerCertificate.Subject }; "
            "$obj=[ordered]@{Status=$sig.Status.ToString(); StatusMessage=$sig.StatusMessage; Signer=$signer}; "
            "$obj | ConvertTo-Json -Compress"
        )

        result = subprocess.run(
            [powershell_path, "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or "signature_command_failed"
            return SignatureInfo(
                status="CommandError",
                signer=None,
                is_signed=False,
                is_trusted=False,
                error=message,
            )

        try:
            payload = json.loads(result.stdout.strip() or "{}")
        except json.JSONDecodeError:
            payload = {}

        status = str(payload.get("Status", "Unknown")).strip() or "Unknown"
        signer = str(payload.get("Signer", "")).strip() or None

        trusted_statuses = {"Valid"}
        unsigned_statuses = {"NotSigned", "NotSupportedFileFormat"}
        is_trusted = status in trusted_statuses
        is_signed = status not in unsigned_statuses and status not in {"Skipped", "Unknown"}

        return SignatureInfo(status=status, signer=signer, is_signed=is_signed, is_trusted=is_trusted)


def _resolve_powershell() -> str:
    candidates = ["pwsh.exe", "powershell.exe"]
    for candidate in candidates:
        if _command_exists(candidate):
            return candidate
    return "powershell.exe"


def _command_exists(command: str) -> bool:
    try:
        subprocess.run(
            [command, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2.0,
        )
        return True
    except Exception:
        return False
