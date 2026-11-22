"""Deterministic package binary, library, and behavioral profile discovery."""

import contextlib
import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Known binary and library fallbacks for common packages when dpkg is unmounted or in container
KNOWN_PACKAGE_BINARIES: dict[str, list[str]] = {
    "libarchive13": ["bsdtar", "bsdcpio", "tar"],
    "tar": ["tar", "gtar"],
    "buildah": ["buildah"],
    "crun": ["crun"],
    "curl": ["curl"],
    "openssh-client": ["ssh", "scp", "sftp"],
    "openssh-server": ["sshd"],
    "systemd": ["systemd", "systemctl", "journalctl"],
    "git": ["git"],
    "bind9-host": ["host", "named"],
    "bind9-libs": ["named", "host", "dig"],
    "libruby3.1": ["ruby", "ruby3.1", "irb", "gem"],
    "ruby3.1": ["ruby", "ruby3.1", "irb", "gem"],
}


class PackageInspector:
    """Discovers binaries, libraries, and execution vectors for a given package."""

    def __init__(self, dpkg_db: str = "/var/lib/dpkg"):
        self.dpkg_db = Path(dpkg_db)

    def discover_binaries(self, package_name: str) -> list[str]:
        """Discover executable binaries associated with a package."""
        clean_name = package_name.lower().split(":")[0]
        binaries: set[str] = set()

        # 1. Read /var/lib/dpkg/info/{clean_name}*.list directly if mounted
        info_dir = self.dpkg_db / "info"
        if info_dir.is_dir():
            candidates = [info_dir / f"{clean_name}.list"]
            with contextlib.suppress(OSError):
                candidates.extend(info_dir.glob(f"{clean_name}:*.list"))
            for list_file in candidates:
                if not list_file.is_file():
                    continue
                with contextlib.suppress(OSError):
                    for line in list_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                        p = line.strip()
                        if p.startswith(("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/")):
                            basename = os.path.basename(p)
                            if basename:
                                binaries.add(basename)

        # 2. Try querying dpkg -L if available
        if shutil.which("dpkg"):
            try:
                res = subprocess.run(
                    ["dpkg", "-L", clean_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        p = line.strip()
                        if p.startswith(("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/")):
                            basename = os.path.basename(p)
                            if basename:
                                binaries.add(basename)
            except (subprocess.SubprocessError, OSError) as err:
                logger.debug("dpkg query failed for %s: %s", clean_name, err)

        # 2. Check known static mapping fallback
        if clean_name in KNOWN_PACKAGE_BINARIES:
            binaries.update(KNOWN_PACKAGE_BINARIES[clean_name])

        # 4. If still empty, use cleaned package name as candidate
        if not binaries:
            candidate = clean_name
            candidate = candidate.removeprefix("lib")
            candidate = candidate.rstrip("0123456789.-")
            if candidate:
                binaries.add(candidate)
            else:
                binaries.add(clean_name)

        return sorted(binaries)
