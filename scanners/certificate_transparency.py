"""Shared contract and factory for certificate-transparency data sources."""

from collections.abc import Iterable
from typing import Protocol


class CertificateLookupError(RuntimeError):
    """A certificate lookup failed, possibly after retrieving partial results."""

    def __init__(
        self,
        message: str,
        *,
        failed_hostnames: dict[str, str] | None = None,
        active_names: set[str] | None = None,
    ):
        super().__init__(message)
        self.failed_hostnames = dict(failed_hostnames or {})
        self.active_names = set(active_names or set())


class CertificateTransparencyProvider(Protocol):
    """Data required by discovery and certificate validation workflows."""

    provider_name: str

    def get_subdomains(self, root_domain: str) -> list[str]:
        """Return normalized hostnames discovered below a root domain."""
        ...

    def get_active_certificate_names(
        self,
        root_domain: str,
        hostnames: Iterable[str] | None = None,
    ) -> set[str]:
        """Return active names; raise CertificateLookupError on lookup failure."""
        ...


def create_certificate_transparency_provider(
    provider_name: str,
    *,
    merklemap_api_token: str = "",
    timeout_connect: float = 8.0,
    timeout_read: float = 30.0,
    max_retries: int = 3,
    request_delay: float = 0.25,
    max_pages: int = 0,
) -> CertificateTransparencyProvider:
    """Create the configured provider without exposing API details to callers."""
    normalized_name = (provider_name or "crtsh").strip().lower()

    if normalized_name == "crtsh":
        from scanners.crtsh_scanner import CrtshScanner

        # Preserve the existing crt.sh behavior when MerkleMap is not enabled.
        return CrtshScanner()

    if normalized_name == "merklemap":
        from scanners.merklemap_provider import MerkleMapProvider

        return MerkleMapProvider(
            api_token=merklemap_api_token,
            timeout_connect=timeout_connect,
            timeout_read=timeout_read,
            max_retries=max_retries,
            request_delay=request_delay,
            max_pages=max_pages or None,
        )

    raise ValueError(
        f"不支援的 CT_PROVIDER: {provider_name!r}，可用值為 crtsh 或 merklemap"
    )
