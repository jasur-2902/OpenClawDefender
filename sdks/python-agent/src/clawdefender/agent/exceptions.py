"""Custom exceptions for the ClawDefender agent package."""

from __future__ import annotations


class ClawDefenderAgentError(Exception):
    """Base exception for all ClawDefender agent errors."""


class GuardNotActiveError(ClawDefenderAgentError):
    """Raised when an operation requires an active guard but none is active."""


class GuardActivationError(ClawDefenderAgentError):
    """Raised when guard activation fails."""


class ClawDefenderNotInstalled(ClawDefenderAgentError):
    """Raised when the ClawDefender binary is not found."""


class DaemonConnectionError(ClawDefenderAgentError):
    """Raised when connection to the ClawDefender daemon fails."""
