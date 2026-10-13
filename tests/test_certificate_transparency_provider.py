"""Unit tests for the certificate-transparency provider boundary."""

import unittest
from collections.abc import Iterable
from unittest.mock import patch

from scanners.certificate_transparency import (
    CertificateLookupError,
    create_certificate_transparency_provider,
)
from scanners.crtsh_scanner import CrtshScanner
from validators.certificate_validator import CertificateValidator


class _FakeResponse:
    def __init__(self, payload: object):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload


class _FakeSession:
    def __init__(self, payload: object):
        self.payload = payload
        self.calls: list[dict[str, object]] = []

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return _FakeResponse(self.payload)


class _FakeProvider:
    provider_name = "fake-ct"

    def __init__(self) -> None:
        self.requested_roots: list[str] = []
        self.requested_hostnames: list[list[str] | None] = []

    def get_subdomains(self, root_domain: str) -> list[str]:
        return []

    def get_active_certificate_names(
        self,
        root_domain: str,
        hostnames: Iterable[str] | None = None,
    ) -> set[str]:
        self.requested_roots.append(root_domain)
        self.requested_hostnames.append(list(hostnames) if hostnames else None)
        return {"example.edu.tw", "*.example.edu.tw"}


class CrtshScannerTests(unittest.TestCase):
    def test_failed_lookup_is_not_reported_as_no_certificates(self) -> None:
        scanner = CrtshScanner()
        with patch.object(scanner, "_fetch_records", return_value=None):
            with self.assertRaises(CertificateLookupError):
                scanner.get_active_certificate_names("example.edu.tw")

    def test_successful_lookup_can_have_no_certificates(self) -> None:
        scanner = CrtshScanner()
        scanner.session = _FakeSession([])
        self.assertEqual(scanner.get_active_certificate_names("example.edu.tw"), set())

    def test_subdomain_query_normalizes_and_filters_names(self) -> None:
        scanner = CrtshScanner()
        scanner.session = _FakeSession(
            [
                {"name_value": "WWW.Example.edu.tw\n*.api.example.edu.tw"},
                {"name_value": "outside.example.org"},
            ]
        )

        result = scanner.get_subdomains("Example.edu.tw.")

        self.assertEqual(
            result,
            ["api.example.edu.tw", "www.example.edu.tw"],
        )
        params = scanner.session.calls[0]["params"]
        self.assertEqual(params, {"q": "%.example.edu.tw", "output": "json"})

    def test_active_certificate_query_preserves_wildcard(self) -> None:
        scanner = CrtshScanner()
        scanner.session = _FakeSession(
            [{"name_value": "Example.edu.tw\n*.Example.edu.tw\n"}]
        )

        result = scanner.get_active_certificate_names("example.edu.tw")

        self.assertEqual(result, {"example.edu.tw", "*.example.edu.tw"})
        params = scanner.session.calls[0]["params"]
        self.assertEqual(params, {"cn": "example.edu.tw", "exclude": "expired"})


class CertificateValidatorProviderTests(unittest.TestCase):
    def test_validator_delegates_lookup_to_provider(self) -> None:
        provider = _FakeProvider()
        validator = CertificateValidator(
            provider=provider,
            database_path="isolated-test.db",
        )

        result = validator._fetch_domain_certificates(
            "example.edu.tw",
            ["www.example.edu.tw"],
        )

        self.assertEqual(result, {"example.edu.tw", "*.example.edu.tw"})
        self.assertEqual(provider.requested_roots, ["example.edu.tw"])
        self.assertEqual(validator.database_path, "isolated-test.db")
        self.assertEqual(
            provider.requested_hostnames,
            [["www.example.edu.tw"]],
        )

    def test_factory_keeps_crtsh_as_default(self) -> None:
        provider = create_certificate_transparency_provider("crtsh")

        self.assertIsInstance(provider, CrtshScanner)
        self.assertEqual(provider.provider_name, "crt.sh")

    def test_factory_rejects_unknown_provider(self) -> None:
        with self.assertRaisesRegex(ValueError, "不支援的 CT_PROVIDER"):
            create_certificate_transparency_provider("unknown")


if __name__ == "__main__":
    unittest.main()
