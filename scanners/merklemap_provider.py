"""MerkleMap certificate-transparency provider."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
import random
import time
from typing import Any
from urllib.parse import quote

import requests

from scanners.certificate_transparency import CertificateLookupError
from utils.logger import get_logger

logger = get_logger("scanners.merklemap_provider")


class MerkleMapProvider:
    """Retrieve subdomains and active certificate names from MerkleMap."""

    API_BASE = "https://api.merklemap.com/v1"
    TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}
    provider_name = "MerkleMap"

    def __init__(
        self,
        api_token: str,
        timeout_connect: float = 8.0,
        timeout_read: float = 30.0,
        max_retries: int = 3,
        request_delay: float = 0.25,
        max_pages: int | None = None,
        *,
        session: requests.Session | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] | None = None,
    ):
        token = (api_token or "").strip()
        if not token:
            raise ValueError("使用 MerkleMap 時必須設定 MERKLEMAP_API_TOKEN")
        if max_retries < 1:
            raise ValueError("MerkleMap max_retries 必須大於等於 1")
        if max_pages is not None and max_pages < 1:
            raise ValueError("MerkleMap max_pages 必須大於等於 1 或設為 None")

        self.timeout = (float(timeout_connect), float(timeout_read))
        self.max_retries = max_retries
        self.request_delay = max(0.0, float(request_delay))
        self.max_pages = max_pages
        self._sleep = sleeper
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._last_request_at: float | None = None

        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "web-calculator-merklemap-provider/1.0",
            }
        )

        self._search_cache: dict[str, list[str]] = {}
        self._certificate_cache: dict[str, list[dict[str, Any]]] = {}
        self._active_names_cache: dict[tuple[str, tuple[str, ...]], set[str]] = {}
        self.request_count = 0
        self.request_counts = {"search": 0, "certificates": 0}

    def get_subdomains(self, root_domain: str) -> list[str]:
        """Search every MerkleMap result page and return normalized hostnames."""
        root = self._normalize_root(root_domain)
        if not root:
            return []

        try:
            matched_hostnames = self._search_hostnames(root)
        except (requests.RequestException, ValueError) as exc:
            logger.warning(f"[MerkleMap] {root} 子網域查詢失敗: {exc}")
            return []

        subdomains = {
            normalized
            for hostname in matched_hostnames
            if (normalized := self._normalize_hostname(hostname))
            and self._is_in_scope(normalized, root)
        }
        logger.info(
            f"[MerkleMap] {root} 搜尋到 {len(matched_hostnames)} 個名稱，"
            f"正規化後 {len(subdomains)} 個子網域"
        )
        return sorted(subdomains)

    def get_active_certificate_names(
        self,
        root_domain: str,
        hostnames: Iterable[str] | None = None,
    ) -> set[str]:
        """Return requested hostnames that have a currently active certificate."""
        root = self._normalize_root(root_domain)
        if not root:
            return set()

        if hostnames is None:
            try:
                candidates = self._search_hostnames(root)
            except (requests.RequestException, ValueError) as exc:
                raise CertificateLookupError(
                    f"[MerkleMap] {root} 憑證候選名稱查詢失敗: {exc}"
                ) from exc
        else:
            candidates = list(hostnames)

        normalized_candidates = tuple(
            sorted(
                {
                    normalized
                    for hostname in candidates
                    if (normalized := self._normalize_certificate_name(hostname))
                    and self._is_in_scope(normalized, root)
                }
            )
        )
        cache_key = (root, normalized_candidates)
        if cache_key in self._active_names_cache:
            return set(self._active_names_cache[cache_key])

        active_names: set[str] = set()
        failures: dict[str, str] = {}
        for index, hostname in enumerate(normalized_candidates, start=1):
            try:
                certificates = self._list_certificates(hostname)
            except (requests.RequestException, ValueError) as exc:
                logger.warning(
                    f"[MerkleMap] {hostname} 詳細憑證查詢失敗 "
                    f"({index}/{len(normalized_candidates)}): {exc}"
                )
                failures[hostname] = str(exc)
                continue

            active_certificates = [
                certificate
                for certificate in certificates
                if self._is_certificate_active(certificate)
            ]
            if not active_certificates:
                continue

            active_names.add(hostname)
            for certificate in active_certificates:
                common_name = self._normalize_certificate_name(
                    certificate.get("subject_common_name")
                )
                if common_name and self._is_in_scope(common_name, root):
                    active_names.add(common_name)

        if failures:
            raise CertificateLookupError(
                f"[MerkleMap] {root} 有 {len(failures)} 個名稱憑證查詢失敗",
                failed_hostnames=failures,
                active_names=active_names,
            )

        self._active_names_cache[cache_key] = set(active_names)
        logger.info(
            f"[MerkleMap] {root} 驗證 {len(normalized_candidates)} 個名稱，"
            f"找到 {len(active_names)} 個有效憑證名稱"
        )
        return active_names

    def _search_hostnames(self, root_domain: str) -> list[str]:
        if root_domain in self._search_cache:
            return list(self._search_cache[root_domain])

        hostnames: list[str] = []
        seen: set[str] = set()
        seen_page_signatures: set[tuple[str, ...]] = set()
        source_rows_seen = 0
        page = 0

        while True:
            payload = self._request_json(
                f"{self.API_BASE}/search",
                params={
                    "query": f"*.{root_domain}",
                    "type": "wildcard",
                    "page": page,
                },
            )
            if not isinstance(payload, dict):
                raise ValueError("MerkleMap search 回傳不是 JSON object")
            results = payload.get("results")
            if not isinstance(results, list):
                raise ValueError("MerkleMap search 回傳缺少 results array")

            source_rows_seen += len(results)
            page_values: list[str] = []
            for item in results:
                if not isinstance(item, dict):
                    continue
                raw_hostname = item.get("hostname") or item.get("domain")
                hostname = self._normalize_certificate_name(raw_hostname)
                if not hostname or not self._is_in_scope(hostname, root_domain):
                    continue
                page_values.append(hostname)
                if hostname not in seen:
                    seen.add(hostname)
                    hostnames.append(hostname)

            page_signature = tuple(page_values)
            if results and page_signature in seen_page_signatures:
                logger.warning(
                    f"[MerkleMap] {root_domain} 第 {page} 頁與前頁重複，停止分頁"
                )
                break
            seen_page_signatures.add(page_signature)

            total = payload.get("count")
            if not results or (isinstance(total, int) and source_rows_seen >= total):
                break
            if self.max_pages is not None and page + 1 >= self.max_pages:
                logger.warning(
                    f"[MerkleMap] {root_domain} 已達頁數上限 {self.max_pages}，"
                    "結果可能不完整"
                )
                break
            page += 1

        self._search_cache[root_domain] = list(hostnames)
        return hostnames

    def _list_certificates(self, hostname: str) -> list[dict[str, Any]]:
        if hostname in self._certificate_cache:
            return list(self._certificate_cache[hostname])

        certificates: list[dict[str, Any]] = []
        seen: set[str] = set()
        page = 0

        while True:
            payload = self._request_json(
                f"{self.API_BASE}/certificates/{quote(hostname, safe='')}",
                params={"page": page},
                allow_not_found=True,
            )
            if payload is None:
                if page > 0:
                    raise ValueError(f"MerkleMap {hostname} 後續憑證分頁不存在")
                break
            if not isinstance(payload, dict):
                raise ValueError(f"MerkleMap {hostname} 憑證回傳不是 JSON object")
            rows = payload.get("certificates")
            if not isinstance(rows, list):
                raise ValueError(f"MerkleMap {hostname} 憑證回傳缺少 certificates array")

            for certificate in rows:
                if not isinstance(certificate, dict):
                    continue
                key = self._certificate_key(certificate)
                if key in seen:
                    continue
                seen.add(key)
                certificates.append(certificate)

            if not rows or not payload.get("has_next_page"):
                break
            if self.max_pages is not None and page + 1 >= self.max_pages:
                raise ValueError(
                    f"[MerkleMap] {hostname} 憑證已達頁數上限 {self.max_pages}，"
                    "結果可能不完整"
                )
            page += 1

        self._certificate_cache[hostname] = list(certificates)
        return certificates

    def _request_json(
        self,
        url: str,
        *,
        params: dict[str, Any],
        allow_not_found: bool = False,
    ) -> Any:
        for attempt in range(1, self.max_retries + 1):
            self._wait_for_rate_limit()
            try:
                self.request_count += 1
                request_kind = "search" if url.endswith("/search") else "certificates"
                self.request_counts[request_kind] += 1
                response = self.session.get(url, params=params, timeout=self.timeout)
                self._last_request_at = time.monotonic()
            except requests.RequestException:
                if attempt >= self.max_retries:
                    raise
                self._sleep(self._retry_delay(None, attempt))
                continue

            if allow_not_found and response.status_code == 404:
                return None
            if (
                response.status_code in self.TRANSIENT_STATUS_CODES
                and attempt < self.max_retries
            ):
                self._sleep(self._retry_delay(response, attempt))
                continue

            response.raise_for_status()
            try:
                return response.json()
            except ValueError as exc:
                raise ValueError("MerkleMap API 回傳無法解析為 JSON") from exc

        raise RuntimeError("MerkleMap request retry loop ended unexpectedly")

    def _wait_for_rate_limit(self) -> None:
        if self.request_delay <= 0 or self._last_request_at is None:
            return
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.request_delay:
            self._sleep(self.request_delay - elapsed)

    @staticmethod
    def _retry_delay(response: requests.Response | None, attempt: int) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    return min(max(float(retry_after), 0.25), 60.0)
                except ValueError:
                    pass
        return min((2 ** (attempt - 1)) + random.uniform(0.0, 0.5), 30.0)

    def _is_certificate_active(self, certificate: dict[str, Any]) -> bool:
        not_after = self._parse_timestamp(certificate.get("not_after"))
        if not_after is None or not_after <= self._utc_now():
            return False
        not_before = self._parse_timestamp(certificate.get("not_before"))
        return not_before is None or not_before <= self._utc_now()

    def _utc_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _certificate_key(certificate: dict[str, Any]) -> str:
        for field in (
            "fingerprint_sha256",
            "sha256",
            "fingerprint_sha1",
            "serial_number",
        ):
            value = certificate.get(field)
            if value:
                return f"{field}:{value}"
        return repr(sorted(certificate.items()))

    @staticmethod
    def _normalize_root(value: Any) -> str:
        hostname = MerkleMapProvider._normalize_hostname(value)
        return hostname or ""

    @staticmethod
    def _normalize_hostname(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        hostname = value.strip().lower().rstrip(".")
        if hostname.startswith("*."):
            hostname = hostname[2:]
        if not hostname or any(char in hostname for char in "/ :"):
            return None
        try:
            return hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    @staticmethod
    def _normalize_certificate_name(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        name = value.strip().lower().rstrip(".")
        wildcard = name.startswith("*.")
        hostname = name[2:] if wildcard else name
        normalized = MerkleMapProvider._normalize_hostname(hostname)
        if not normalized:
            return None
        return f"*.{normalized}" if wildcard else normalized

    @staticmethod
    def _is_in_scope(hostname: str, root_domain: str) -> bool:
        scope_name = hostname.removeprefix("*.")
        return scope_name == root_domain or scope_name.endswith(f".{root_domain}")
