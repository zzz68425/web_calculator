"""Resolve address and alias records using explicit DNS server settings."""

import dns.exception
import dns.resolver

from utils.logger import get_logger

logger = get_logger("utils.dns")


def resolve_ips(
    domain: str,
    dns_servers: list[str],
) -> tuple[
    list[str], list[str], int | None, int | None, int | None, list[str]
]:
    """Return addresses, record flags, and first-hop CNAME targets."""
    ipv4_list: list[str] = []
    ipv6_list: list[str] = []
    has_a: int | None = None
    has_aaaa: int | None = None
    has_cname: int | None = None
    cname_targets: list[str] = []

    try:
        resolver = dns.resolver.Resolver()
        nameservers = [
            server.strip()
            for server in (dns_servers or [])
            if server and server.strip()
        ]
        if nameservers:
            resolver.nameservers = nameservers
    except Exception as exc:
        logger.debug(f"建立 DNS Resolver 失敗，使用預設解析器：{exc}")
        resolver = dns.resolver.Resolver()

    try:
        ans4 = resolver.resolve(domain, "A", lifetime=3.0)
        if ans4:
            ipv4_list = [record.to_text() for record in ans4]
            has_a = 1
    except (
        dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout
    ) as exc:
        logger.debug(f"DNS A 預解析失敗 {domain}: {exc}")
    except Exception as exc:
        logger.debug(f"DNS A 預解析未預期錯誤 {domain}: {exc}")

    try:
        ans6 = resolver.resolve(domain, "AAAA", lifetime=3.0)
        if ans6:
            ipv6_list = [record.to_text() for record in ans6]
            has_aaaa = 1
    except (
        dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout
    ) as exc:
        logger.debug(f"DNS AAAA 預解析失敗 {domain}: {exc}")
    except Exception as exc:
        logger.debug(f"DNS AAAA 預解析未預期錯誤 {domain}: {exc}")

    try:
        ans_cname = resolver.resolve(domain, "CNAME", lifetime=3.0)
        if ans_cname:
            has_cname = 1
            cname_targets = [
                str(record.target).rstrip(".").lower()
                for record in ans_cname
                if getattr(record, "target", None)
            ]
    except (
        dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout
    ) as exc:
        logger.debug(f"DNS CNAME 預解析失敗 {domain}: {exc}")
    except Exception as exc:
        logger.debug(f"DNS CNAME 預解析未預期錯誤 {domain}: {exc}")

    return ipv4_list, ipv6_list, has_a, has_aaaa, has_cname, cname_targets
