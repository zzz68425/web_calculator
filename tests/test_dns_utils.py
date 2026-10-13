"""Offline DNS tests covering explicit settings and partial failures."""

import unittest
from unittest.mock import Mock, call, patch

import dns.exception
import dns.resolver

from utils.dns import resolve_ips


class DnsUtilsTests(unittest.TestCase):
    def test_configured_servers_and_all_record_types_are_preserved(self):
        resolver = Mock()
        resolver.resolve.side_effect = [
            [Mock(to_text=Mock(return_value="192.0.2.1")),
             Mock(to_text=Mock(return_value="192.0.2.2"))],
            [Mock(to_text=Mock(return_value="2001:db8::1"))],
            [Mock(target="HOSTING.EXAMPLE.COM.")],
        ]
        servers = [" 8.8.8.8 ", "", "1.1.1.1"]

        with patch("utils.dns.dns.resolver.Resolver", return_value=resolver):
            result = resolve_ips("www.example.edu.tw", servers)

        self.assertEqual(result, (
            ["192.0.2.1", "192.0.2.2"], ["2001:db8::1"],
            1, 1, 1, ["hosting.example.com"],
        ))
        self.assertEqual(resolver.nameservers, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(servers, [" 8.8.8.8 ", "", "1.1.1.1"])
        self.assertEqual(resolver.resolve.call_args_list, [
            call("www.example.edu.tw", "A", lifetime=3.0),
            call("www.example.edu.tw", "AAAA", lifetime=3.0),
            call("www.example.edu.tw", "CNAME", lifetime=3.0),
        ])

    def test_one_record_failure_does_not_discard_other_records(self):
        resolver = Mock()
        resolver.resolve.side_effect = [
            dns.exception.Timeout(),
            [Mock(to_text=Mock(return_value="2001:db8::1"))],
            dns.resolver.NXDOMAIN(),
        ]
        with patch("utils.dns.dns.resolver.Resolver", return_value=resolver):
            result = resolve_ips("www.example.edu.tw", [])
        self.assertEqual(result, ([], ["2001:db8::1"], None, 1, None, []))

    def test_empty_server_settings_keep_system_defaults(self):
        resolver = Mock(nameservers=["192.0.2.53"])
        resolver.resolve.return_value = []
        with patch("utils.dns.dns.resolver.Resolver", return_value=resolver):
            result = resolve_ips("www.example.edu.tw", ["", "  "])
        self.assertEqual(resolver.nameservers, ["192.0.2.53"])
        self.assertEqual(result, ([], [], None, None, None, []))

    def test_all_record_failures_return_existing_empty_result_format(self):
        resolver = Mock()
        resolver.resolve.side_effect = [
            dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN(),
            dns.exception.Timeout(),
        ]
        with patch("utils.dns.dns.resolver.Resolver", return_value=resolver):
            result = resolve_ips("missing.example.edu.tw", [])
        self.assertEqual(result, ([], [], None, None, None, []))

    def test_resolver_initialization_failure_uses_default_resolver(self):
        resolver = Mock()
        resolver.resolve.return_value = []
        with patch("utils.dns.dns.resolver.Resolver", side_effect=[
            RuntimeError("unavailable resolver configuration"), resolver,
        ]) as factory:
            result = resolve_ips("www.example.edu.tw", ["8.8.8.8"])
        self.assertEqual(factory.call_count, 2)
        self.assertEqual(result, ([], [], None, None, None, []))


if __name__ == "__main__":
    unittest.main()
