"""Coordinate domain discovery, validation, and database persistence."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional

from config import Config
from database.repository import DatabaseManagerORM as DatabaseManager
from domain_hierarchy import build_domain_hierarchy
from models.website import Website
from scanners.certificate_transparency import (
    create_certificate_transparency_provider,
)
from scanners.dns_zone_scanner import DnsZoneScanner
from scanners.shodan_fqdn import ShodanFqdnScanner
from scanners.shodan_scanner import ShodanScanner, fetch_shodan_http_batch
from scanners.virustotal_scanner import VirusTotalScanner
from utils.dns import resolve_ips
from utils.domain import extract_root_domain, infer_storage_root
from utils.logger import get_logger
from utils.network import rate_limit
from validators.certificate_validator import CertificateValidator
from validators.otx_validator import OtxValidator

logger = get_logger("website_finder")


class WebsiteFinder:
    """網站發現主程式"""
    
    def __init__(self, config: Config):
        self.config = config
        self.db_manager = DatabaseManager(config.DATABASE_PATH)
        self.shodan_scanner = ShodanScanner(config.SHODAN_API_KEY, self.db_manager)
        self.shodan_fqdn_scanner = ShodanFqdnScanner(config.SHODAN_API_KEY)
        self.certificate_provider = create_certificate_transparency_provider(
            config.CT_PROVIDER,
            merklemap_api_token=config.MERKLEMAP_API_TOKEN,
            timeout_connect=config.CONNECT_TIMEOUT,
            timeout_read=config.READ_TIMEOUT,
            max_retries=config.MERKLEMAP_MAX_RETRIES,
            request_delay=config.MERKLEMAP_REQUEST_DELAY,
            max_pages=config.MERKLEMAP_MAX_PAGES,
        )
        logger.info(
            f"CT provider: {self.certificate_provider.provider_name}"
        )
        self.dns_zone_scanner = DnsZoneScanner(config)
        # VirusTotal 支援多組 key：直接傳整個列表（或單一）
        self.vt_scanner = VirusTotalScanner(config.VIRUSTOTAL_API_KEYS)
        self.validator = OtxValidator(config)
        self.certificate_validator = CertificateValidator(
            provider=self.certificate_provider,
            database_path=config.DATABASE_PATH,
        )

    def _save_websites_by_storage_root(
        self,
        websites: List[Website],
        area_domains: set[str],
        when_latest_otx_checked: Optional[datetime] = None,
    ) -> int:
        """Save each website under its inferred root using explicit area rules."""
        saved = 0
        for website in websites:
            storage_root = infer_storage_root(website.fqdn, area_domains)
            if self.db_manager.save_website(
                website,
                root_domain_name=storage_root,
                when_latest_otx_checked=when_latest_otx_checked,
            ):
                saved += 1
        return saved

    def _complete_scan_target(
        self,
        scan_target_id: int,
        target: str,
        certificate_groups: dict[str, set[str]],
        checked_hostnames: set[str],
        request_counts_before: dict[str, int],
    ) -> bool:
        """Finish certificate checks before committing a target's done state."""
        failures: dict[str, str] = {}
        checked = updated = no_certificate = 0
        logger.info(f"[憑證] {target} 開始本批憑證驗證")
        try:
            # Empty discovery batches still need a record for the queried root.
            build_domain_hierarchy(
                self.db_manager, [target], sorted(certificate_groups)
            )
            for root, hosts in sorted(certificate_groups.items()):
                candidates = sorted(hosts - checked_hostnames)
                if not candidates:
                    continue
                try:
                    result = self.certificate_validator.validate_root_domain(
                        root, candidates
                    )
                    checked += result.checked_count
                    updated += result.updated_count
                    no_certificate += result.no_certificate_count
                    failures.update(result.failures)
                    checked_hostnames.update(result.checked_hostnames)
                except Exception as exc:
                    failures.update((host, str(exc)) for host in candidates)
                    logger.error(f"[憑證] {root} 驗證失敗: {exc}")
        except Exception as exc:
            failures[target] = str(exc)
            logger.error(f"[憑證] {target} 階層建立失敗: {exc}")

        logger.info(
            f"[憑證] {target} 檢查 {checked} 筆，更新 {updated} 筆，"
            f"無有效憑證 {no_certificate} 筆，失敗 {len(failures)} 筆"
        )
        counts = getattr(self.certificate_provider, "request_counts", {})
        if counts:
            search_count = (
                counts.get("search", 0) - request_counts_before.get("search", 0)
            )
            cert_count = (
                counts.get("certificates", 0)
                - request_counts_before.get("certificates", 0)
            )
            logger.info(
                f"[MerkleMap API] {target} 本批請求數：搜尋 {search_count}、"
                f"詳細憑證 {cert_count}、合計 {search_count + cert_count}（含重試）"
            )

        if failures:
            details = "; ".join(
                f"{host}: {reason}"
                for host, reason in list(failures.items())[:5]
            )
            message = f"憑證階段失敗 {len(failures)} 筆: {details}"
            self.db_manager.mark_scan_target_failed(scan_target_id, message)
            logger.error(f"[續跑] {target} {message}，保留為 failed，繼續下一個目標")
            return False

        self.db_manager.mark_scan_target_done(scan_target_id)
        logger.info(f"[續跑] {target} 憑證階段完成，標記為 done")
        return True
    
    def run(self, cert_pattern: str, quick_mode: bool = False, skip_xlsx: bool = False, resume: bool = False) -> List[Website]:
        """執行完整的搜尋流程
        
        Args:
            cert_pattern: 憑證搜尋模式
            quick_mode: 快速模式，限制查詢範圍
            skip_xlsx: 跳過 xlsx 匯入，只使用 Shodan 結果
            resume: 從上一個未完成的 scan_run 繼續
        """
        logger.info("="*60)
        logger.info(f"開始搜尋憑證: {cert_pattern}")
        if resume:
            logger.info("模式: 從上次中斷處繼續")
        elif skip_xlsx:
            logger.info("模式: 只查詢 Shodan 結果（跳過 xlsx）")
        else:
            logger.info("模式: Shodan + xlsx 合併查詢")
        logger.info("="*60)

        if resume:
            run_info = self.db_manager.get_latest_resumable_scan_run(cert_pattern)
            if not run_info:
                logger.warning(f"[續跑] 找不到 cert_pattern={cert_pattern} 的未完成任務")
                return []

            run_id, saved_mode, saved_status = run_info
            reset_count = self.db_manager.prepare_scan_run_for_resume(run_id)
            scan_targets = self.db_manager.get_scan_targets(run_id, include_done=False)
            logger.info(
                f"[續跑] 使用 scan_run id={run_id}，原模式={saved_mode}，"
                f"原狀態={saved_status}，重置 running target {reset_count} 筆，待處理 {len(scan_targets)} 筆"
            )
        else:
            # 步驟 1: Shodan 搜尋
            logger.info("步驟 1: Shodan 搜尋")
            shodan_result = self.shodan_scanner.scan(
                cert_pattern,
                country=self.config.DEFAULT_COUNTRY,
                port=self.config.DEFAULT_PORT
            )
            
            if not shodan_result.domains:
                logger.warning("Shodan 沒有找到相關域名")
            else:
                logger.info(f"Shodan 找到 {len(shodan_result.domains)} 個域名")
            
            # 取得 Shodan 的 VT 目標
            shodan_vt_targets = shodan_result.vt_query_targets if shodan_result.vt_query_targets else shodan_result.domains
            shodan_vt_set = set(shodan_vt_targets) if shodan_vt_targets else set()
            shodan_imported = self.db_manager.import_shodan_vt_targets(list(shodan_vt_targets or []))
            logger.info(f"Shodan VT 目標匯入 root_domain 新增 {shodan_imported} 筆")
            
            # 步驟 1.5: 匯入 xlsx 的 root_domain 並合併（可跳過）
            if skip_xlsx:
                logger.info("步驟 1.5: 跳過 xlsx 匯入（模式 2）")
                target_sources = [(target, "shodan") for target in list(shodan_vt_targets or [])]
                logger.info(f"VT 查詢目標：只有 Shodan {len(target_sources)} 個")
            else:
                logger.info("步驟 1.5: 匯入 xlsx root_domain 並合併 Shodan 結果")
                xlsx_imported = self.db_manager.import_root_domains_from_xlsx("institution")
                logger.info(f"xlsx 匯入了 {xlsx_imported} 個新的 root_domain")
                
                # 取得 xlsx 的 root_domain（source='xlsx'）
                xlsx_root_domains = self.db_manager.get_all_root_domains(source="xlsx")
                
                # 合併：Shodan 優先，xlsx 補充（去除已存在於 Shodan 結果的）
                xlsx_only = [rd for rd in xlsx_root_domains if rd not in shodan_vt_set]
                target_sources = (
                    [(target, "shodan") for target in list(shodan_vt_targets or [])]
                    + [(target, "xlsx") for target in xlsx_only]
                )
                
                logger.info(f"合併後 VT 查詢目標：Shodan {len(shodan_vt_set)} 個 + xlsx 補充 {len(xlsx_only)} 個 = 共 {len(target_sources)} 個")
            
            if not target_sources:
                logger.warning("沒有任何 VT 查詢目標（Shodan + xlsx 皆為空）")
                return []

            # 快速模式：限制查詢目標
            if quick_mode:
                target_sources = target_sources[:1]  # 只處理第一個域名
                logger.info(f"🚀 快速模式：限制為 {len(target_sources)} 個目標")

            mode = "shodan_only" if skip_xlsx else "full"
            run_id = self.db_manager.create_scan_run(cert_pattern=cert_pattern, mode=mode)
            self.db_manager.create_scan_targets(run_id, target_sources)
            scan_targets = self.db_manager.get_scan_targets(run_id, include_done=False)

        if not scan_targets:
            logger.warning("沒有任何 VT 查詢目標（Shodan + xlsx 皆為空）")
            if resume:
                self.db_manager.mark_scan_run_completed(run_id)
            return []
        
        # 步驟 2 + 3 改為「逐個 VT 目標域名即時處理」：
        #   1) 取該 root domain 的 subdomains
        #   2) 預先寫入（DNS 預解析）
        #   3) 立即執行 OTX 驗證並更新該批
        logger.info("步驟 2: VirusTotal 獲得subdomains並即時 OTX 驗證")
        
        if resume and quick_mode:
            scan_targets = scan_targets[:1]
            logger.info(f"🚀 快速模式：本次續跑限制為 {len(scan_targets)} 個待處理目標")

        logger.info(f"共有 {len(scan_targets)} 個待處理 VT 查詢目標 (VT Keys: {len(self.config.VIRUSTOTAL_API_KEYS)})，將逐一處理")

        processed_subdomains: set[str] = set()  # 避免跨 root 重複處理
        certificate_checked_hostnames: set[str] = set()
        aggregated_validated: List[Website] = []
        
        # 取得 area domains 用於 Shodan FQDN 判斷
        area_domains = self.db_manager.get_all_area_domains()
        searched_area_domains: set[str] = set()  # 記錄已查過 Shodan FQDN 的 area domain
        logger.info(f"載入 {len(area_domains)} 個 area domain 用於 Shodan FQDN 判斷") 

        for idx, (scan_target_id, target_index, target, target_status, target_source) in enumerate(scan_targets, start=1):
            logger.info("-" * 50)
            logger.info(
                f"[VT+Shodan DNS] ({idx}/{len(scan_targets)}) 處理 root domain: {target} "
                f"(scan_target_id={scan_target_id}, 原序={target_index}, source={target_source}, status={target_status})"
            )
            self.db_manager.mark_scan_target_running(scan_target_id)
            request_counts_before = dict(
                getattr(self.certificate_provider, "request_counts", {})
            )
            
            # 1. Shodan DNS API 查詢邏輯：
            #    - 如果 target 的 root domain 是 area → 只查一次該 area domain
            #    - 如果不是 area → 正常查 target
            shodan_results = []
            shodan_subdomains = []
            root_of_target = extract_root_domain(target)
            
            if root_of_target in area_domains:
                # target 屬於 area（例如 ytes.ntpc.edu.tw，root = ntpc.edu.tw）
                if root_of_target not in searched_area_domains:
                    # 這個 area 還沒查過 → 查 area domain
                    logger.info(f"[Shodan DNS] {target} 屬於 area {root_of_target}，查詢 area domain")
                    shodan_results = self.shodan_fqdn_scanner.get_subdomains_with_a_record(root_of_target)
                    shodan_subdomains = [result["fqdn"] for result in shodan_results]
                    searched_area_domains.add(root_of_target)
                    logger.info(f"[Shodan DNS] area {root_of_target} 取得 {len(shodan_subdomains)} 個子網域（已記錄，後續同 area 不再查）")
                else:
                    # 這個 area 已經查過 → 跳過 Shodan FQDN
                    logger.info(f"[Shodan DNS] {target} 屬於已查過的 area {root_of_target}，跳過 Shodan FQDN")
            else:
                # 不是 area → 正常查詢
                shodan_results = self.shodan_fqdn_scanner.get_subdomains_with_a_record(target)
                shodan_subdomains = [result["fqdn"] for result in shodan_results]
                logger.info(f"[Shodan DNS] {target} 取得 {len(shodan_subdomains)} 個 A/AAAA/CNAME record 子網域")
            
            # 2. 再用 VT 取得子網域
            vt_subdomains = self._get_subdomains_with_delay(target)
            logger.info(f"[VT] {target} 取得 {len(vt_subdomains)} 個子網域")

            # 3. 再用 CT provider 取得子網域
            ct_subdomains = self.certificate_provider.get_subdomains(target)
            provider_name = self.certificate_provider.provider_name
            logger.info(
                f"[{provider_name}] {target} 取得 {len(ct_subdomains)} 個子網域"
            )
            
            # 4. 合併去重：VT + Shodan + CT provider，相同的只保留一個
            all_subs_set = set(vt_subdomains)  # 先放 VT 的
            all_subs_set.update(shodan_subdomains)  # 再加 Shodan 的（自動去重）
            all_subs_set.update(ct_subdomains)  # 再加 CT provider（自動去重）
            all_subdomains = list(all_subs_set)
            
            overlap_vt_shodan = len(set(shodan_subdomains) & set(vt_subdomains))
            overlap_vt_ct = len(set(vt_subdomains) & set(ct_subdomains))
            overlap_shodan_ct = len(set(shodan_subdomains) & set(ct_subdomains))
            logger.info(
                f"[合併] {target} 合併後共 {len(all_subdomains)} 個子網域 "
                f"（VT+Shodan 重疊 {overlap_vt_shodan}、"
                f"VT+{provider_name} 重疊 {overlap_vt_ct}、"
                f"Shodan+{provider_name} 重疊 {overlap_shodan_ct}）"
            )
            
            certificate_groups: dict[str, set[str]] = {}
            for fqdn in [target, *all_subdomains]:
                fqdn = fqdn.strip().lower().rstrip(".")
                storage_root = infer_storage_root(fqdn, area_domains)
                certificate_groups.setdefault(storage_root, set()).update(
                    [storage_root, fqdn]
                )

            if not all_subdomains:
                logger.info(f"[合併] {target} 無子域名，僅進行根網域憑證驗證")
                self._complete_scan_target(
                    scan_target_id, target, certificate_groups,
                    certificate_checked_hostnames, request_counts_before,
                )
                continue

            # 去掉已處理過的重複子域名
            new_subs = [s for s in all_subdomains if s not in processed_subdomains]
            skipped = len(all_subdomains) - len(new_subs)
            if skipped:
                logger.info(f"[合併] {target} 略過 {skipped} 個已處理過的重複子域名")
            if not new_subs:
                self._complete_scan_target(
                    scan_target_id, target, certificate_groups,
                    certificate_checked_hostnames, request_counts_before,
                )
                continue

            # 預先寫入（未驗證 when_latest_otx_checked=None）
            # 現在所有 IP 都由 DNS 預解析取得（Shodan 只提供 FQDN 清單）
            # 使用多執行緒並行 DNS 解析
            dns_results: dict[str, tuple[List[str], List[str], int | None, int | None, int | None, List[str]]] = {}
            dns_workers = min(20, len(new_subs))  # 最多 20 個執行緒
            
            logger.info(f"[DNS] 開始並行解析 {len(new_subs)} 個子網域（執行緒數: {dns_workers}）")
            with ThreadPoolExecutor(max_workers=dns_workers) as executor:
                future_to_sub = {
                    executor.submit(resolve_ips, sub, self.config.DNS_SERVERS): sub
                    for sub in new_subs
                }
                for future in as_completed(future_to_sub):
                    sub = future_to_sub[future]
                    try:
                        ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets = future.result()
                        dns_results[sub] = (ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets)
                    except Exception as e:
                        logger.debug(f"[DNS] 解析 {sub} 失敗: {e}")
                        dns_results[sub] = ([], [], None, None, None, [])
            
            prelist: List[Website] = []
            unresolved = 0
            for sub in new_subs:
                ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets = dns_results.get(sub, ([], [], None, None, None, []))
                if not (ipv4_list or ipv6_list):
                    unresolved += 1
                # Website 不再需要傳入 ip 參數，改用 ipv4_list/ipv6_list 屬性
                w = Website(fqdn=sub, url=f"http://{sub}")
                # 將雙協定結果附加為屬性（列表形式）
                setattr(w, "ipv4_list", ipv4_list)
                setattr(w, "ipv6_list", ipv6_list)
                # DNS 紀錄存在旗標
                setattr(w, "has_a", has_a)
                setattr(w, "has_aaaa", has_aaaa)
                setattr(w, "has_cname", has_cname)
                setattr(w, "cname_targets", cname_targets)
                prelist.append(w)

            # 步驟 2.5: 域名階層分解（在 OTX 驗證前）
            logger.info(f"[域名階層] 開始分解 {target} 的域名階層")
            try:
                hierarchy_roots = sorted({
                    infer_storage_root(fqdn, area_domains)
                    for fqdn in [target, *all_subdomains]
                })
                domain_id_map = build_domain_hierarchy(
                    db_manager=self.db_manager,
                    all_fqdns=[target, *all_subdomains],
                    root_domains=hierarchy_roots
                )
                logger.info(f"[域名階層] {target} 使用 {len(hierarchy_roots)} 個 root，建立了 {len(domain_id_map)} 個域名階層關係")
            except Exception as e:
                logger.error(f"[域名階層] {target} 域名階層分解失敗： {e}")
                # 繼續後續步驟，但可能會有問題

            pre_saved = self._save_websites_by_storage_root(
                prelist, area_domains, when_latest_otx_checked=None
            )
            logger.info(f"[DB] {target} 預先寫入 {pre_saved} 筆 (未驗證 when_latest_otx_checked=None)，DNS 未解析 {unresolved} 筆")

            # 步驟 2.6: DNS Zone (SOA/NS) 掃描並入庫
            logger.info(f"[DNS Zone] 掃描 {target} 的 {len(new_subs)} 個子網域 SOA/NS")
            try:
                zone_info = self.dns_zone_scanner.get_zone_info_batch(new_subs)
                zones_saved, links_saved = self.db_manager.save_dns_zone_batch(zone_info)
                logger.info(f"[DNS Zone] {target} 儲存 zone {zones_saved} 筆、domain-zone 關聯 {links_saved} 筆")
            except Exception as e:
                logger.error(f"[DNS Zone] {target} 掃描或儲存失敗: {e}")

            # 立即 OTX 驗證這批新子域名
            logger.info(f"[OTX] 驗證 {target} 的 {len(new_subs)} 個子域名")
            validated = self.validator.validate_websites(new_subs)
            if not validated:
                logger.warning(f"[OTX] {target} 無成功驗證子域名")

            # 寫回驗證成功 (覆寫 IP 差異 + when_latest_otx_checked=當前時間)
            updated = 0
            current_time = datetime.now()
            for site in validated:
                try:
                    existing = self.db_manager.get_website_by_fqdn(site.fqdn)
                except Exception:
                    existing = None
                # 不再根據 OTX 覆寫或提示 IP 差異（OTX 僅作存在性驗證）
                # 若 OTX 回傳未帶出 v4/v6，盡量沿用預存紀錄的雙協定資訊
                if not hasattr(site, "ipv4") and existing and hasattr(existing, "ipv4"):
                    setattr(site, "ipv4", getattr(existing, "ipv4", None))
                if not hasattr(site, "ipv6") and existing and hasattr(existing, "ipv6"):
                    setattr(site, "ipv6", getattr(existing, "ipv6", None))
                storage_root = infer_storage_root(site.fqdn, area_domains)
                if self.db_manager.save_website(site, root_domain_name=storage_root, when_latest_otx_checked=current_time):
                    updated += 1
            logger.info(f"[DB] {target} 更新驗證成功 {updated} 筆 (when_latest_otx_checked={current_time.strftime('%Y-%m-%d %H:%M:%S')})")

            # 步驟 3.5: 取得並儲存 OTX HTTP Scans 資料
            validated_fqdns = [site.fqdn for site in validated]
            logger.info(f"[OTX HTTP Scans] 取得 {target} 的 {len(validated_fqdns)} 個已驗證域名的 http_scans")
            try:
                http_scans_dict = self.validator.fetch_http_scans_batch(validated_fqdns)
                if http_scans_dict:
                    saved_count = self.db_manager.save_http_scans_batch(http_scans_dict)
                    logger.info(f"[DB] {target} 儲存 {saved_count} 筆 http_scans 資料")
                else:
                    logger.info(f"[OTX HTTP Scans] {target} 無 http_scans 資料")
            except Exception as e:
                logger.error(f"[OTX HTTP Scans] 取得或儲存 {target} 的 http_scans 失敗: {e}")

            # 步驟 3.6: Shodan HTTP 查詢與 IoT 標記
            # 改為對本批 new_subs 全量查詢，不再受 OTX 驗證結果限制
            shodan_targets = list(dict.fromkeys(new_subs))
            logger.info(f"[Shodan HTTP] 查詢 {target} 的 {len(shodan_targets)} 個 subdomain（全量）")
            try:
                known_ips_by_subdomain: dict[str, set[str]] = {}
                for fqdn in shodan_targets:
                    try:
                        website = self.db_manager.get_website_by_fqdn(fqdn)
                    except Exception:
                        website = None
                    if not website:
                        continue

                    known_ips: set[str] = set()
                    known_ips.update(getattr(website, "ipv4_list", []) or [])
                    known_ips.update(getattr(website, "ipv6_list", []) or [])
                    if getattr(website, "ipv4", None):
                        known_ips.add(website.ipv4)
                    if getattr(website, "ipv6", None):
                        known_ips.add(website.ipv6)
                    if known_ips:
                        known_ips_by_subdomain[fqdn] = known_ips

                html_data, product_data = fetch_shodan_http_batch(
                    api_key=self.config.SHODAN_API_KEY,
                    subdomains=shodan_targets,
                    delay=1.0,
                    known_ips_by_subdomain=known_ips_by_subdomain,
                    max_workers=6,
                )
                if html_data:
                    saved = self.db_manager.save_shodan_http_batch(html_data)
                    logger.info(f"[Shodan HTTP] {target} 儲存 {saved} 筆 http.html 資料")
                else:
                    logger.info(f"[Shodan HTTP] {target} 無 http.html 資料")
                
                if product_data:
                    saved_products = self.db_manager.save_shodan_product_batch(product_data)
                    logger.info(f"[Shodan Product] {target} 儲存 {saved_products} 筆 product 資料")
                else:
                    logger.info(f"[Shodan Product] {target} 無 product 資料")
            except Exception as e:
                logger.error(f"[Shodan HTTP] {target} 查詢失敗: {e}")

            aggregated_validated.extend(validated)
            processed_subdomains.update(new_subs)
            self._complete_scan_target(
                scan_target_id, target, certificate_groups,
                certificate_checked_hostnames, request_counts_before,
            )

        remaining_targets = self.db_manager.get_scan_targets(run_id, include_done=False)
        if remaining_targets:
            if any(status == "failed" for _, _, _, status, _ in remaining_targets):
                self.db_manager.mark_scan_run_failed(run_id)
            logger.info(f"[續跑] scan_run id={run_id} 仍有 {len(remaining_targets)} 個 target 尚未完成")
        else:
            self.db_manager.mark_scan_run_completed(run_id)
            logger.info(f"[續跑] scan_run id={run_id} 已全部完成")

        if not aggregated_validated:
            logger.warning("整體流程結束：沒有任何子域名通過 OTX 驗證")
            return []

        # 最終統計顯示
        self._display_statistics(aggregated_validated)
        return aggregated_validated
    
    @rate_limit(2.0)  # VirusTotal API 速率限制（外部再做一層保守限制）
    def _get_subdomains_with_delay(self, domain: str) -> List[str]:
        """帶延遲的子域名查詢"""
        return self.vt_scanner.get_subdomains(domain)
    
    def _display_statistics(self, websites: List[Website]) -> None:
        """顯示統計資訊"""
        logger.info("="*60)
        logger.info("搜尋結果統計")
        logger.info("="*60)
        
        if websites:
            logger.info(f"找到 {len(websites)} 個可連線的網站:")
            for i, site in enumerate(websites, 1):
                logger.info(f"{i:2d}. {site.url}")
                if site.redirect_to:
                    logger.info(f"    重定向到: {site.redirect_to}")
        
        # 資料庫統計
        total_count, unique_ips = self.db_manager.get_statistics()
        logger.info(f"資料庫統計:")
        logger.info(f"  總域名數: {total_count}")
        logger.info(f"  獨特 IP 數: {unique_ips}")
