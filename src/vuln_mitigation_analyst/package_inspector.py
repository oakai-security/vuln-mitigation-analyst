"""Deterministic package binary, library, and behavioral profile discovery."""

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
}


class PackageInspector:
    """Discovers binaries, libraries, and execution vectors for a given package."""

    def __init__(self, dpkg_db: str = "/var/lib/dpkg"):
        self.dpkg_db = Path(dpkg_db)

    def discover_binaries(self, package_name: str) -> list[str]:
        """Discover executable binaries associated with a package."""
        clean_name = package_name.lower().split(":")[0]
        binaries: set[str] = set()

        # 1. Try querying dpkg -L if available
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

        # 3. If still empty, use cleaned package name as candidate
        if not binaries:
            candidate = clean_name.replace("lib", "").rstrip("0123456789-")
            if candidate:
                binaries.add(candidate)
            else:
                binaries.add(clean_name)

        return sorted(binaries)
