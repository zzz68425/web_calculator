# validators/certificate_validator.py
"""
憑證驗證器 - 使用可替換的 CT provider 檢查主機的 SSL 憑證
改進版：批量查詢 root domain 憑證，減少 API 呼叫
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set
from datetime import datetime
import time
import random

from sqlalchemy import column, select, table, update

from database.session import create_session_factory, db_session
from database.models import Domain
from config import Config
from scanners.certificate_transparency import (
    CertificateLookupError,
    CertificateTransparencyProvider,
)
from scanners.crtsh_scanner import CrtshScanner
from utils.logger import get_logger

logger = get_logger("validators.certificate_validator")


@dataclass
class CertificateValidationResult:
    """Keep missing certificates separate from failed requests or writes."""

    checked_count: int = 0
    updated_count: int = 0
    no_certificate_count: int = 0
    failures: dict[str, str] = field(default_factory=dict)
    checked_hostnames: set[str] = field(default_factory=set)


class CertificateValidator:
    """使用 CT provider 驗證主機憑證的驗證器（批量模式）。"""

    def __init__(
        self,
        timeout: int = 30,
        base_delay: float = 2.0,
        provider: CertificateTransparencyProvider | None = None,
        database_path: str | None = None,
    ):
        self.timeout = timeout
        self.base_delay = base_delay
        self.provider = provider or CrtshScanner(timeout_read=float(timeout))
        self.database_path = database_path or Config.DATABASE_PATH

    def _fetch_domain_certificates(
        self,
        root_domain: str,
        hostnames: List[str] | None = None,
    ) -> Set[str]:
        """
        獲取指定 root domain 的所有憑證名稱
        
        Args:
            root_domain: 根域名（如 ncku.edu.tw）
            
        Returns:
            包含所有憑證名稱的 set
        """
        try:
            logger.info(
                f"[{self.provider.provider_name}] 查詢 {root_domain} 的有效憑證資料..."
            )
            return self.provider.get_active_certificate_names(root_domain, hostnames)
        except Exception as e:
            logger.error(
                f"[{self.provider.provider_name}] 查詢 {root_domain} 憑證時"
                f"發生未預期錯誤: {e}"
            )
            raise

    def validate_root_domain(
        self,
        root_domain: str,
        hostnames: List[str],
    ) -> CertificateValidationResult:
        """Validate only this batch, using its explicit storage root."""
        root = root_domain.strip().lower().rstrip(".")
        hosts = sorted({
            host.strip().lower().rstrip(".") for host in hostnames if host.strip()
        })
        if not root or any(
            host != root and not host.endswith("." + root) for host in hosts
        ):
            raise ValueError("憑證驗證清單必須屬於指定的 root domain")

        result = CertificateValidationResult()
        if not hosts:
            return result

        engine, session_factory = create_session_factory(self.database_path)
        try:
            # Use only requested FQDNs, not every hierarchy node in the database.
            fqdn_view = table("fqdn", column("id"), column("name"))
            domain_ids: dict[str, int] = {}
            with db_session(session_factory) as session:
                for start in range(0, len(hosts), 400):
                    names = [host + "." for host in hosts[start : start + 400]]
                    rows = session.execute(
                        select(fqdn_view.c.id, fqdn_view.c.name)
                        .where(fqdn_view.c.name.in_(names))
                    ).all()
                    domain_ids.update(
                        (name.rstrip("."), domain_id) for domain_id, name in rows
                    )

            for host in hosts:
                if host not in domain_ids:
                    result.failures[host] = "找不到域名記錄，無法完成憑證驗證"
            candidates = [host for host in hosts if host in domain_ids]
            if not candidates:
                return result

            try:
                cert_names = self._fetch_domain_certificates(root, candidates)
            except CertificateLookupError as exc:
                cert_names = exc.active_names
                failures = exc.failed_hostnames or {host: str(exc) for host in candidates}
                result.failures.update(
                    (host, reason) for host, reason in failures.items() if host in domain_ids
                )
            except Exception as exc:
                result.failures.update((host, str(exc)) for host in candidates)
                return result

            for host in candidates:
                if host in result.failures:
                    continue
                result.checked_count += 1
                wildcard = "*." + host.split(".", 1)[1] if "." in host else ""
                if host not in cert_names and wildcard not in cert_names:
                    result.no_certificate_count += 1
                    result.checked_hostnames.add(host)
                    continue

                try:
                    with db_session(session_factory) as session:
                        updated = session.execute(
                            update(Domain)
                            .where(Domain.id == domain_ids[host])
                            .values(when_latest_certificate_checked=datetime.now())
                        )
                        if updated.rowcount != 1:
                            raise RuntimeError("找不到域名記錄，憑證檢查時間更新失敗")
                    result.updated_count += 1
                    result.checked_hostnames.add(host)
                except Exception as exc:
                    result.failures[host] = str(exc)
            return result
        finally:
            session_factory.remove()
            engine.dispose()

    def _update_certificate_check_time(self, domain_id: int, hostname: str) -> bool:
        """
        更新主機的憑證檢查時間為當前時間
        
        Args:
            domain_id: Domain ID
            hostname: 主機名稱 (僅用於 log)
            
        Returns:
            True 如果更新成功，False 則否
        """
        try:
            engine, SessionFactory = create_session_factory(self.database_path)
            with db_session(SessionFactory) as session:
                current_time = datetime.now()
                result = session.execute(
                    update(Domain)
                    .where(Domain.id == domain_id)
                    .values(when_latest_certificate_checked=current_time)
                )
                
                if result.rowcount > 0:
                    logger.debug(f"已更新 {hostname} (id={domain_id}) 的憑證檢查時間: {current_time}")
                    return True
                else:
                    logger.warning(f"找不到主機記錄: {hostname} (id={domain_id})")
                    return False
                    
        except Exception as e:
            logger.error(f"更新憑證檢查時間失敗 {hostname}: {e}")
            return False

    def _get_domains_by_root_domain(self) -> Dict[str, List[tuple[int, str]]]:
        """
        按 root domain 分組取得所有主機 (id, fqdn)
        
        Returns:
            {root_domain: [(id, fqdn), ...]} 的字典
        """
        engine, SessionFactory = create_session_factory(self.database_path)
        
        with db_session(SessionFactory) as session:
            from database.models import RootDomain
            
            # 取得所有 domain 資料
            domains = session.execute(select(Domain)).scalars().all()
            domain_map = {d.id: d for d in domains}
            
            # 取得所有 root domain
            root_domains = session.execute(select(RootDomain)).scalars().all()
            root_map = {r.id: r.name for r in root_domains}
            
            result: Dict[str, List[tuple[int, str]]] = {}
            
            for domain in domains:
                if not domain.root_id or domain.root_id not in root_map:
                    continue
                
                root_name = root_map[domain.root_id]
                
                # 重建 FQDN
                parts = [domain.leftmost_label]
                current = domain
                while current.parent_domain_id:
                    if current.parent_domain_id in domain_map:
                        current = domain_map[current.parent_domain_id]
                        parts.append(current.leftmost_label)
                    else:
                        break
                
                # 組合 FQDN
                fqdn = ".".join(parts)
                
                if root_name not in result:
                    result[root_name] = []
                result[root_name].append((domain.id, fqdn))
                
            return result

    def validate_all_domains(self) -> tuple[int, int]:
        """
        驗證資料庫中所有主機的憑證（批量模式）
        
        Returns:
            (checked_count, updated_count) - 檢查的主機數量與成功更新時間的數量
        """
        domain_domains = self._get_domains_by_root_domain()
        
        if not domain_domains:
            logger.info("資料庫中沒有主機記錄")
            return 0, 0
        
        total_domains = sum(len(domains) for domains in domain_domains.values())
        logger.info(f"開始批量驗證 {total_domains} 個主機的憑證，分佈在 {len(domain_domains)} 個 root domain")
        
        checked_count = 0
        updated_count = 0
        
        for root_domain, domains in domain_domains.items():
            logger.info(f"處理 {root_domain}，包含 {len(domains)} 個主機...")
            
            # 獲取該 root domain 的所有憑證名稱
            cert_names = self._fetch_domain_certificates(
                root_domain,
                [hostname for _, hostname in domains],
            )
            
            if not cert_names:
                logger.warning(f"無法取得 {root_domain} 的憑證資料，跳過...")
                checked_count += len(domains)
                continue
            
            # 檢查每個主機是否在憑證清單中
            for domain_id, hostname in domains:
                checked_count += 1
                
                # 檢查主機名稱是否在憑證名稱集合中
                # 也檢查通配符憑證（如 *.example.com）
                has_certificate = False
                
                if hostname in cert_names:
                    has_certificate = True
                else:
                    # 檢查通配符憑證
                    hostname_parts = hostname.split('.')
                    if len(hostname_parts) > 1:
                        wildcard_name = '*.' + '.'.join(hostname_parts[1:])
                        if wildcard_name in cert_names:
                            has_certificate = True
                
                if has_certificate:
                    if self._update_certificate_check_time(domain_id, hostname):
                        updated_count += 1
                        logger.debug(f"✓ {hostname} 有有效憑證")
                else:
                    logger.debug(f"✗ {hostname} 沒有找到憑證")
            
            logger.info(f"完成 {root_domain}：檢查了 {len(domains)} 個主機")
            
            # 各 domain 間的延遲
            time.sleep(self.base_delay + random.uniform(0.5, 1.5))
        
        logger.info(f"批量憑證驗證完成: 檢查了 {checked_count} 個主機，更新了 {updated_count} 個憑證檢查時間")
        return checked_count, updated_count

    def validate_specific_domains(self, hostnames: List[str]) -> tuple[int, int]:
        """
        驗證指定主機清單的憑證
        
        Args:
            hostnames: 要檢查的主機名稱清單
            
        Returns:
            (checked_count, updated_count) - 檢查的主機數量與成功更新時間的數量
        """
        if not hostnames:
            return 0, 0
        
        # 將主機按 root domain 分組（更智慧的提取邏輯）
        domain_hosts: Dict[str, List[str]] = {}
        
        for hostname in hostnames:
            # 更智慧的 root domain 提取
            parts = hostname.split('.')
            if len(parts) >= 3:
                # 對於 xxx.yyy.edu.tw 這樣的域名，取 yyy.edu.tw
                root_domain = '.'.join(parts[-3:])
            elif len(parts) >= 2:
                # 對於 xxx.yyy 這樣的域名，取 xxx.yyy
                root_domain = '.'.join(parts[-2:])
            else:
                root_domain = hostname
            
            if root_domain not in domain_hosts:
                domain_hosts[root_domain] = []
            domain_hosts[root_domain].append(hostname)
        
        logger.info(f"開始驗證指定的 {len(hostnames)} 個主機憑證，涵蓋 {len(domain_hosts)} 個 domain")
        
        checked_count = 0
        updated_count = 0
        
        # 需要 DatabaseManagerORM 來查找 domain_id
        from database.repository import DatabaseManagerORM
        db_manager = DatabaseManagerORM(self.database_path)
        
        for root_domain, hosts in domain_hosts.items():
            logger.info(f"查詢 {root_domain} 的憑證...")
            
            # 獲取該 root domain 的所有憑證名稱
            cert_names = self._fetch_domain_certificates(root_domain, hosts)
            
            if not cert_names:
                logger.warning(f"無法取得 {root_domain} 的憑證資料")
                checked_count += len(hosts)
                continue
            
            # 檢查每個主機
            for hostname in hosts:
                checked_count += 1
                
                has_certificate = False
                
                if hostname in cert_names:
                    has_certificate = True
                else:
                    # 檢查通配符憑證
                    hostname_parts = hostname.split('.')
                    if len(hostname_parts) > 1:
                        wildcard_name = '*.' + '.'.join(hostname_parts[1:])
                        if wildcard_name in cert_names:
                            has_certificate = True
                
                if has_certificate:
                    # 查找 domain_id
                    with db_session(db_manager.SessionFactory) as session:
                        domain = db_manager._find_domain_by_fqdn(session, hostname)
                        if domain:
                            if self._update_certificate_check_time(domain.id, hostname):
                                updated_count += 1
                        else:
                            logger.warning(f"找不到域名記錄: {hostname}")
                    
                    logger.info(f"✓ {hostname} 有有效憑證")
                else:
                    logger.info(f"✗ {hostname} 沒有找到憑證")
            
            # domain 間延遲
            time.sleep(self.base_delay)
        
        logger.info(f"指定主機憑證驗證完成: 檢查了 {checked_count} 個主機，更新了 {updated_count} 個憑證檢查時間")
        return checked_count, updated_count
