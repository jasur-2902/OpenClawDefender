"""Auto-installation support for the ClawDefender binary."""

from __future__ import annotations

import logging
import os
import platform
import shutil
from typing import Optional

from .exceptions import ClawDefenderNotInstalled

logger = logging.getLogger("clawdefender.agent")

BINARY_NAME = "clawdefender"
GITHUB_RELEASE_BASE = "https://github.com/clawdefender/clawdefender/releases/latest/download"


def find_binary() -> Optional[str]:
    """Locate the ClawDefender binary on the system.

    Checks:
    1. CLAWDEFENDER_BIN environment variable
    2. ~/.local/bin/clawdefender
    3. System PATH
    """
    # Check environment variable
    env_path = os.environ.get("CLAWDEFENDER_BIN")
    if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
        return env_path

    # Check common install location
    local_path = os.path.expanduser(f"~/.local/bin/{BINARY_NAME}")
    if os.path.isfile(local_path) and os.access(local_path, os.X_OK):
        return local_path

    # Check system PATH
    found = shutil.which(BINARY_NAME)
    if found:
        return found

    return None


def is_installed() -> bool:
    """Check if ClawDefender binary is available."""
    return find_binary() is not None


def _get_platform_asset() -> str:
    """Determine the correct release asset name for this platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "aarch64"
    else:
        arch = machine

    if system == "linux":
        return f"clawdefender-{arch}-unknown-linux-gnu.tar.gz"
    elif system == "darwin":
        return f"clawdefender-{arch}-apple-darwin.tar.gz"
    elif system == "windows":
        return f"clawdefender-{arch}-pc-windows-msvc.zip"
    else:
        raise ClawDefenderNotInstalled(f"Unsupported platform: {system}/{machine}")


def download_url() -> str:
    """Return the download URL for the current platform."""
    asset = _get_platform_asset()
    return f"{GITHUB_RELEASE_BASE}/{asset}"


def ensure_installed(consent: Optional[bool] = None) -> str:
    """Ensure ClawDefender is installed, optionally downloading it.

    Parameters
    ----------
    consent:
        - ``None``: interactive mode — prompt user for permission (not implemented
          in this package; raises if not installed).
        - ``True``: pre-authorized — download without prompting.
        - ``False``: fallback-only — raise if not installed.

    Returns
    -------
    str
        Path to the ClawDefender binary.

    Raises
    ------
    ClawDefenderNotInstalled
        If the binary cannot be found and consent is not granted.
    """
    path = find_binary()
    if path:
        return path

    if consent is False:
        raise ClawDefenderNotInstalled(
            "ClawDefender binary not found. Install it from "
            "https://github.com/clawdefender/clawdefender/releases"
        )

    if consent is None:
        raise ClawDefenderNotInstalled(
            "ClawDefender binary not found. Set consent=True to auto-install, "
            "or install manually from https://github.com/clawdefender/clawdefender/releases"
        )

    # consent=True — attempt download
    return _download_and_install()


def _download_and_install() -> str:
    """Download the binary from GitHub releases and install to ~/.local/bin/."""
    import tempfile

    url = download_url()
    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)
    install_path = os.path.join(install_dir, BINARY_NAME)

    logger.info("Downloading ClawDefender from %s", url)

    try:
        import httpx

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, "clawdefender-archive")
            with httpx.stream("GET", url, follow_redirects=True) as resp:
                resp.raise_for_status()
                with open(archive_path, "wb") as f:
                    for chunk in resp.iter_bytes():
                        f.write(chunk)

            # Extract
            if archive_path.endswith(".zip") or url.endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(archive_path) as zf:
                    zf.extractall(tmpdir)
            else:
                import tarfile
                with tarfile.open(archive_path) as tf:
                    tf.extractall(tmpdir)

            # Find the binary in extracted files
            for root, _dirs, files in os.walk(tmpdir):
                if BINARY_NAME in files:
                    src = os.path.join(root, BINARY_NAME)
                    shutil.copy2(src, install_path)
                    os.chmod(install_path, 0o755)
                    logger.info("Installed ClawDefender to %s", install_path)
                    return install_path

        raise ClawDefenderNotInstalled("Binary not found in downloaded archive")

    except ClawDefenderNotInstalled:
        raise
    except Exception as exc:
        raise ClawDefenderNotInstalled(
            f"Failed to download ClawDefender: {exc}"
        ) from exc
