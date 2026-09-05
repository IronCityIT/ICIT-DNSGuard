"""Error types the control plane raises. Every one maps to an HTTP status in the
API layer, so they are part of the public contract, not internal detail."""

from __future__ import annotations


class DnsGuardError(Exception):
    """Base for everything this package raises."""

    status_code = 500


class ValidationError(DnsGuardError):
    """The caller sent something that cannot be acted on."""

    status_code = 400


class NotFoundError(DnsGuardError):
    """The addressed object does not exist for this tenant."""

    status_code = 404


class ConflictError(DnsGuardError):
    """The object exists but is not in a state where this action is legal."""

    status_code = 409


class TenantIsolationError(DnsGuardError):
    """A caller reached for something belonging to a different tenant.

    Always a bug or an attack; never a routine outcome.
    """

    status_code = 403


class ApprovalRequiredError(DnsGuardError):
    """A disruptive action was attempted without an approval that authorises it.

    Carries the request that was opened so the caller can route it for sign-off.
    """

    status_code = 202

    def __init__(self, message: str, request_id: str = "", action: str = "") -> None:
        super().__init__(message)
        self.request_id = request_id
        self.action = action


class UpstreamError(DnsGuardError):
    """A dependency the control plane does not own failed."""

    status_code = 502


class CircuitOpenError(UpstreamError):
    """A dependency is failing and calls to it are being shed deliberately."""

    status_code = 503
