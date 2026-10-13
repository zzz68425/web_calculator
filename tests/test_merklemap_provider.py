"""Offline tests for the MerkleMap CT provider."""

from datetime import datetime, timezone
import unittest
from typing import Any

import requests

from scanners.merklemap_provider import MerkleMapProvider
from scanners.certificate_transparency import CertificateLookupError


class _FakeResponse:
    def __init__(
        self,
        payload: object,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ):
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            response = requests.Response()
            response.status_code = self.status_code
            raise requests.HTTPError(
                f"HTTP {self.status_code}",
                response=response,
            )

    def json(self) -> object:
        return self.payload


class _FakeSession:
    def __init__(self, responses: list[_FakeResponse]):
        self.responses = list(responses)
        self.headers: dict[str, str] = {}
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if not self.responses:
            raise AssertionError(f"Unexpected request: {url}")
        return self.responses.pop(0)


class MerkleMapProviderTests(unittest.TestCase):
    def _provider(
        self,
        responses: list[_FakeResponse],
        *,
        sleeper=lambda _: None,
    ) -> MerkleMapProvider:
        return MerkleMapProvider(
            "test-token",
            request_delay=0,
            session=_FakeSession(responses),
            sleeper=sleeper,
            now=lambda: datetime(2026, 9, 30, tzinfo=timezone.utc),
        )

    def test_search_reads_all_pages_and_normalizes_wildcards(self) -> None:
        provider = self._provider(
            [
                _FakeResponse(
                    {
                        "count": 3,
                        "results": [
                            {"hostname": "api.example.edu.tw"},
                            {"hostname": "*.example.edu.tw"},
                        ],
                    }
                ),
                _FakeResponse(
                    {
                        "count": 3,
                        "results": [{"hostname": "WWW.Example.edu.tw."}],
                    }
                ),
            ]
        )

        result = provider.get_subdomains("Example.edu.tw.")

        self.assertEqual(
            result,
            ["api.example.edu.tw", "example.edu.tw", "www.example.edu.tw"],
        )
        self.assertEqual(len(provider.session.calls), 2)
        self.assertEqual(provider.request_count, 2)
        self.assertEqual(provider.request_counts["search"], 2)
        self.assertEqual(provider.session.calls[0]["params"]["page"], 0)
        self.assertEqual(provider.session.calls[1]["params"]["page"], 1)

    def test_active_names_exclude_expired_and_future_certificates(self) -> None:
        provider = self._provider(
            [
                _FakeResponse(
                    {
                        "certificates": [
                            {
                                "fingerprint_sha256": "active",
                                "subject_common_name": "*.example.edu.tw",
                                "not_before": "2026-01-01T00:00:00Z",
                                "not_after": "2027-01-01T00:00:00Z",
                            },
                            {
                                "fingerprint_sha256": "expired",
                                "subject_common_name": "api.example.edu.tw",
                                "not_before": "2020-01-01T00:00:00Z",
                                "not_after": "2021-01-01T00:00:00Z",
                            },
                            {
                                "fingerprint_sha256": "future",
                                "subject_common_name": "api.example.edu.tw",
                                "not_before": "2027-01-01T00:00:00Z",
                                "not_after": "2028-01-01T00:00:00Z",
                            },
                        ],
                        "has_next_page": False,
                    }
                ),
                _FakeResponse({}, status_code=404),
            ]
        )

        result = provider.get_active_certificate_names(
            "example.edu.tw",
            ["api.example.edu.tw", "missing.example.edu.tw"],
        )

        self.assertEqual(
            result,
            {"api.example.edu.tw", "*.example.edu.tw"},
        )
        self.assertEqual(len(provider.session.calls), 2)
        self.assertEqual(provider.request_counts["certificates"], 2)

    def test_transient_error_uses_retry_after(self) -> None:
        delays: list[float] = []
        provider = self._provider(
            [
                _FakeResponse({}, status_code=429, headers={"Retry-After": "2"}),
                _FakeResponse({"count": 0, "results": []}),
            ],
            sleeper=delays.append,
        )

        self.assertEqual(provider.get_subdomains("example.edu.tw"), [])
        self.assertEqual(delays, [2.0])
        self.assertEqual(len(provider.session.calls), 2)
        self.assertEqual(provider.request_count, 2)

    def test_partial_failure_keeps_successes_and_does_not_cache_failure(self) -> None:
        active = {
            "certificates": [{"not_after": "2027-01-01T00:00:00Z"}],
            "has_next_page": False,
        }
        provider = self._provider(
            [_FakeResponse({}, status_code=502) for _ in range(3)]
            + [_FakeResponse(active), _FakeResponse(active)]
        )
        hosts = ["a.example.edu.tw", "b.example.edu.tw"]

        with self.assertRaises(CertificateLookupError) as raised:
            provider.get_active_certificate_names("example.edu.tw", hosts)

        self.assertEqual(set(raised.exception.failed_hostnames), {hosts[0]})
        self.assertEqual(raised.exception.active_names, {hosts[1]})
        self.assertEqual(provider.request_counts["certificates"], 4)
        self.assertEqual(
            provider.get_active_certificate_names("example.edu.tw", hosts),
            set(hosts),
        )
        self.assertEqual(provider.request_counts["certificates"], 5)

    def test_no_certificates_is_a_successful_empty_result(self) -> None:
        provider = self._provider([_FakeResponse({}, status_code=404)])
        self.assertEqual(
            provider.get_active_certificate_names("example.edu.tw", ["example.edu.tw"]),
            set(),
        )

    def test_truncated_certificate_pages_are_not_reported_as_complete(self) -> None:
        provider = self._provider([
            _FakeResponse({"certificates": [{"not_after": "2027-01-01T00:00:00Z"}],
                           "has_next_page": True}),
        ])
        provider.max_pages = 1

        with self.assertRaises(CertificateLookupError):
            provider.get_active_certificate_names("example.edu.tw", ["example.edu.tw"])

        self.assertNotIn("example.edu.tw", provider._certificate_cache)

    def test_missing_followup_page_is_a_failure_not_an_empty_result(self) -> None:
        provider = self._provider([
            _FakeResponse({"certificates": [{"not_after": "2027-01-01T00:00:00Z"}],
                           "has_next_page": True}),
            _FakeResponse({}, status_code=404),
        ])
        with self.assertRaises(CertificateLookupError):
            provider.get_active_certificate_names("example.edu.tw", ["example.edu.tw"])
        self.assertNotIn("example.edu.tw", provider._certificate_cache)


if __name__ == "__main__":
    unittest.main()
