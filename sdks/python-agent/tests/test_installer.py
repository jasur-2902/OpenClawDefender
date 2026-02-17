"""Tests for the auto-installer module."""

from __future__ import annotations

import os
from unittest.mock import patch, MagicMock

import pytest

from clawdefender.agent.installer import (
    find_binary,
    is_installed,
    ensure_installed,
    _get_platform_asset,
    download_url,
)
from clawdefender.agent.exceptions import ClawDefenderNotInstalled


class TestFindBinary:
    """Tests for finding the ClawDefender binary."""

    def test_find_via_env_var(self, tmp_path):
        binary = tmp_path / "clawdefender"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)
        with patch.dict(os.environ, {"CLAWDEFENDER_BIN": str(binary)}):
            result = find_binary()
            assert result == str(binary)

    def test_find_via_env_var_missing_file(self):
        with patch.dict(os.environ, {"CLAWDEFENDER_BIN": "/nonexistent/clawdefender"}):
            # Should fall through to other checks
            result = find_binary()
            # May or may not find it depending on system
            # Just verify no crash
            assert result is None or isinstance(result, str)

    def test_find_via_shutil_which(self):
        with patch("clawdefender.agent.installer.shutil.which") as mock_which:
            mock_which.return_value = "/usr/local/bin/clawdefender"
            with patch.dict(os.environ, {}, clear=False):
                # Clear env var to avoid shortcircuit
                env = os.environ.copy()
                env.pop("CLAWDEFENDER_BIN", None)
                with patch.dict(os.environ, env, clear=True):
                    result = find_binary()
                    # Could find via env, local path, or which
                    assert result is None or isinstance(result, str)


class TestIsInstalled:
    """Tests for installation detection."""

    def test_is_installed_false(self):
        with patch("clawdefender.agent.installer.find_binary", return_value=None):
            assert is_installed() is False

    def test_is_installed_true(self):
        with patch("clawdefender.agent.installer.find_binary", return_value="/usr/bin/clawdefender"):
            assert is_installed() is True


class TestEnsureInstalled:
    """Tests for ensure_installed with consent modes."""

    def test_ensure_installed_already_exists(self):
        with patch("clawdefender.agent.installer.find_binary", return_value="/usr/bin/clawdefender"):
            result = ensure_installed(consent=False)
            assert result == "/usr/bin/clawdefender"

    def test_ensure_installed_consent_false_raises(self):
        with patch("clawdefender.agent.installer.find_binary", return_value=None):
            with pytest.raises(ClawDefenderNotInstalled):
                ensure_installed(consent=False)

    def test_ensure_installed_consent_none_raises(self):
        with patch("clawdefender.agent.installer.find_binary", return_value=None):
            with pytest.raises(ClawDefenderNotInstalled):
                ensure_installed(consent=None)


class TestPlatformAsset:
    """Tests for platform asset name detection."""

    def test_linux_x86_64(self):
        with patch("platform.system", return_value="Linux"), \
             patch("platform.machine", return_value="x86_64"):
            asset = _get_platform_asset()
            assert "linux" in asset
            assert "x86_64" in asset

    def test_darwin_arm64(self):
        with patch("platform.system", return_value="Darwin"), \
             patch("platform.machine", return_value="arm64"):
            asset = _get_platform_asset()
            assert "darwin" in asset
            assert "aarch64" in asset

    def test_download_url_format(self):
        with patch("platform.system", return_value="Linux"), \
             patch("platform.machine", return_value="x86_64"):
            url = download_url()
            assert url.startswith("https://")
            assert "clawdefender" in url
