"""
crt.sh 子網域掃描器
從 crt.sh JSON 回傳中擷取 name_value 並去重。
"""

from __future__ import annotations

import random
import time
from collections.abc import Iterable
from typing import List, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from scanners.certificate_transparency import CertificateLookupError
from utils.logger import get_logger

logger = get_logger("scanners.crtsh_scanner")


class CrtshScanner:
    """使用 crt.sh 取得子網域與有效憑證名稱。"""

    BASE_URL = "https://crt.sh/json"
    provider_name = "crt.sh"

    def __init__(
        self,
        timeout_connect: float = 8.0,
        timeout_read: float = 20.0,
        max_retries: int = 3,
        backoff_base: float = 1.0,
    ):
        self.timeout_connect = timeout_connect
        self.timeout_read = timeout_read
        self.max_retries = max_retries
        self.backoff_base = backoff_base

        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                )
            }
        )

    def get_subdomains(self, root_domain: str) -> List[str]:
        """
        查詢 root_domain 的 crt.sh 憑證資料，從 name_value 擷取子網域。

        Args:
            root_domain: 例如 ncku.edu.tw

        Returns:
            去重排序後的 FQDN 清單
        """
        root = (root_domain or "").strip().lower().rstrip(".")
        if not root:
            return []

        records = self._fetch_records(
            root,
            params={"q": f"%.{root}", "output": "json"},
            operation="子網域查詢",
        )
        if records is None:
            return []

        subdomains = self._extract_from_name_value(records, root)
        logger.info(
            f"[crt.sh] {root} 原始 {len(records)} 筆，去重後 {len(subdomains)} 個子網域"
        )
        return subdomains

    def get_active_certificate_names(
        self,
        root_domain: str,
        hostnames: Iterable[str] | None = None,
    ) -> Set[str]:
        """取得 root domain 目前未過期憑證涵蓋的 DNS 名稱。"""
        root = (root_domain or "").strip().lower().rstrip(".")
        if not root:
            return set()

        records = self._fetch_records(
            root,
            params={"cn": root, "exclude": "expired"},
            operation="有效憑證查詢",
        )
        if records is None:
            raise CertificateLookupError(f"[crt.sh] {root} 有效憑證查詢失敗")

        certificate_names = self._extract_certificate_names(records)
        logger.info(
            f"[crt.sh] {root} 取得 {len(certificate_names)} 個有效憑證名稱"
        )
        return certificate_names

    def _fetch_records(
        self,
        root_domain: str,
        params: dict[str, str],
        operation: str,
    ) -> list[dict] | None:
        """執行 crt.sh JSON 查詢，集中處理重試與錯誤。"""

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.get(
                    self.BASE_URL,
                    params=params,
                    timeout=(self.timeout_connect, self.timeout_read),
                )
                resp.raise_for_status()
                data = resp.json()

                if not isinstance(data, list):
                    logger.warning(
                        f"[crt.sh] {root_domain} {operation}回傳格式非 list，忽略"
                    )
                    return None
                return data

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt >= self.max_retries:
                    logger.warning(
                        f"[crt.sh] {root_domain} {operation}連線/逾時最終失敗: {e}"
                    )
                    return None
                delay = self._backoff_delay(attempt)
                logger.warning(
                    f"[crt.sh] {root_domain} {operation}連線/逾時失敗 "
                    f"(attempt {attempt}/{self.max_retries})，{delay:.2f}s 後重試: {e}"
                )
                time.sleep(delay)

            except requests.exceptions.RequestException as e:
                if attempt >= self.max_retries:
                    logger.warning(
                        f"[crt.sh] {root_domain} {operation} HTTP 請求最終失敗: {e}"
                    )
                    return None
                delay = self._backoff_delay(attempt)
                logger.warning(
                    f"[crt.sh] {root_domain} {operation} HTTP 請求失敗 "
                    f"(attempt {attempt}/{self.max_retries})，{delay:.2f}s 後重試: {e}"
                )
                time.sleep(delay)

            except ValueError as e:
                # JSON 解析錯誤
                logger.warning(
                    f"[crt.sh] {root_domain} {operation} JSON 解析失敗: {e}"
                )
                return None

            except Exception as e:
                logger.warning(
                    f"[crt.sh] {root_domain} {operation}發生未預期錯誤: {e}"
                )
                return None

        return None

    def _extract_from_name_value(self, records: list[dict], root_domain: str) -> List[str]:
        """從 crt.sh records 的 name_value 欄位擷取並去重。"""
        out: Set[str] = set()

        for rec in records:
            raw = (rec or {}).get("name_value")
            if not raw:
                continue

            # name_value 可能包含多行名稱
            for line in str(raw).splitlines():
                fqdn = line.strip().lower().rstrip(".")
                if not fqdn:
                    continue
                if fqdn.startswith("*."):
                    fqdn = fqdn[2:]
                if not fqdn:
                    continue

                if fqdn == root_domain or fqdn.endswith("." + root_domain):
                    out.add(fqdn)

        return sorted(out)

    @staticmethod
    def _extract_certificate_names(records: list[dict]) -> Set[str]:
        """從 name_value 擷取憑證名稱，保留 wildcard 供驗證使用。"""
        names: Set[str] = set()
        for record in records:
            raw = (record or {}).get("name_value")
            if not raw:
                continue
            for part in str(raw).splitlines():
                name = part.strip().lower().rstrip(".")
                if name:
                    names.add(name)
        return names

    def _backoff_delay(self, attempt: int) -> float:
        # exponential backoff + jitter
        base = self.backoff_base * (2 ** max(0, attempt - 1))
        return base + random.uniform(0.0, 0.5)
