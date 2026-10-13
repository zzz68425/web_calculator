"""Offline workflow tests using real temporary SQLite databases."""

from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import dns.resolver
import requests
from sqlalchemy import delete, select

from config import Config
from database.models import Domain, RootDomain, ScanRun, ScanTarget
from database.repository import DatabaseManagerORM
from database.session import db_session
from domain_hierarchy import build_domain_hierarchy
from website_finder import WebsiteFinder
from models.website import ShodanResult, Website
from scanners.certificate_transparency import CertificateLookupError
from scanners.merklemap_provider import MerkleMapProvider
from validators.certificate_validator import CertificateValidator


class _Provider:
    provider_name = "offline-ct"

    def __init__(self, discoveries, events):
        self.discoveries = discoveries
        self.events = events
        self.lookups = []
        self.fail_roots = set()
        self.interrupt_root = None
        self.active_names = None
        self.on_lookup = None
        self.request_counts = {"search": 0, "certificates": 0}

    def get_subdomains(self, root):
        self.events.append(("discovery", root))
        self.request_counts["search"] += 1
        return list(self.discoveries.get(root, []))

    def get_active_certificate_names(self, root, hostnames=None):
        hosts = list(hostnames or [])
        self.events.append(("certificate", root))
        self.lookups.append((root, hosts))
        self.request_counts["certificates"] += len(hosts)
        if self.on_lookup:
            self.on_lookup(root, hosts)
        if root == self.interrupt_root:
            raise KeyboardInterrupt
        if root in self.fail_roots:
            raise CertificateLookupError(
                "offline timeout after retries",
                failed_hostnames={hosts[0]: "offline timeout"},
                active_names=set(hosts[1:]),
            )
        return set(hosts) if self.active_names is None else set(self.active_names)


class CertificateBatchWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        tmp = self.stack.enter_context(TemporaryDirectory(prefix="edit-cert-test-"))
        self.database_path = str(Path(tmp) / "test.db")
        self.stack.enter_context(patch.object(Config, "CITY_DOMAIN_CSV_PATH", ""))
        self.stack.enter_context(patch("requests.sessions.Session.request",
                                       side_effect=AssertionError("Live HTTP is forbidden")))
        self.resolver = Mock()
        self.resolver.resolve.side_effect = dns.resolver.NoAnswer
        self.stack.enter_context(patch(
            "utils.dns.dns.resolver.Resolver", return_value=self.resolver,
        ))
        self.db = DatabaseManagerORM(self.database_path)
        self.stack.callback(self.db.engine.dispose)
        self.stack.callback(self.db.SessionFactory.remove)
        self.events = []
        self.shodan_http = self.stack.enter_context(patch(
            "website_finder.fetch_shodan_http_batch", side_effect=self._shodan_http,
        ))

    def _shodan_http(self, **kwargs):
        self.events.append(("shodan", tuple(kwargs["subdomains"])))
        return {}, {}

    def _finder(self, discoveries, otx_success=True):
        finder = WebsiteFinder.__new__(WebsiteFinder)
        finder.config = Config(
            DATABASE_PATH=self.database_path,
            SHODAN_API_KEY="offline-key",
            VIRUSTOTAL_API_KEYS=["offline-key"],
            DNS_SERVERS=[],
        )
        finder.db_manager = self.db
        roots = list(discoveries)
        finder.shodan_scanner = Mock()
        finder.shodan_scanner.scan.return_value = ShodanResult(
            domains=roots, vt_query_targets=roots,
        )
        finder.shodan_fqdn_scanner = Mock()
        finder.shodan_fqdn_scanner.get_subdomains_with_a_record.return_value = []
        finder._get_subdomains_with_delay = Mock(return_value=[])
        finder.certificate_provider = _Provider(discoveries, self.events)
        finder.certificate_validator = CertificateValidator(
            provider=finder.certificate_provider,
            database_path=self.database_path,
            base_delay=0,
        )
        finder.dns_zone_scanner = Mock()
        finder.dns_zone_scanner.get_zone_info_batch.return_value = {}
        finder.validator = Mock()
        finder.validator.validate_websites.side_effect = (
            lambda hosts: [Website(fqdn=host) for host in hosts] if otx_success else []
        )
        finder.validator.fetch_http_scans_batch.return_value = {}
        finder._display_statistics = Mock()
        return finder

    def _states(self):
        with db_session(self.db.SessionFactory) as session:
            targets = session.execute(select(ScanTarget).order_by(ScanTarget.target_index)).scalars().all()
            run = session.execute(select(ScanRun).order_by(ScanRun.id.desc())).scalars().first()
            return {t.target: t.status for t in targets}, run.status

    def _checked_time(self, hostname):
        with db_session(self.db.SessionFactory) as session:
            return self.db._find_domain_by_fqdn(session, hostname).when_latest_certificate_checked

    def test_each_root_finishes_certificates_before_next_root_and_skips_old_nodes(self):
        build_domain_hierarchy(self.db, ["old.alpha.edu.tw", "www.other.edu.tw"],
                               ["alpha.edu.tw", "other.edu.tw"])
        finder = self._finder({
            "alpha.edu.tw": ["www.lab.alpha.edu.tw"],
            "beta.edu.tw": ["www.beta.edu.tw"],
        })
        finder.config.DNS_SERVERS = ["1.1.1.1"]
        states_during_lookup = []
        finder.certificate_provider.on_lookup = lambda *_: states_during_lookup.append(self._states())

        with patch.object(finder.certificate_validator, "validate_all_domains",
                          side_effect=AssertionError("Whole database lookup is forbidden")):
            finder.run("*.alpha.edu.tw", skip_xlsx=True)

        self.assertLess(self.events.index(("certificate", "alpha.edu.tw")),
                        self.events.index(("discovery", "beta.edu.tw")))
        self.assertEqual(finder.certificate_provider.lookups, [
            ("alpha.edu.tw", ["alpha.edu.tw", "www.lab.alpha.edu.tw"]),
            ("beta.edu.tw", ["beta.edu.tw", "www.beta.edu.tw"]),
        ])
        self.assertEqual(states_during_lookup[0],
                         ({"alpha.edu.tw": "running", "beta.edu.tw": "pending"}, "running"))
        self.assertEqual(states_during_lookup[1],
                         ({"alpha.edu.tw": "done", "beta.edu.tw": "running"}, "running"))
        self.assertEqual(self._states(),
                         ({"alpha.edu.tw": "done", "beta.edu.tw": "done"}, "completed"))
        self.assertIsInstance(self._checked_time("www.lab.alpha.edu.tw"), datetime)
        self.assertIsNone(self._checked_time("lab.alpha.edu.tw"))
        self.assertIsNone(self._checked_time("old.alpha.edu.tw"))
        self.assertIsNone(self._checked_time("www.other.edu.tw"))
        self.assertEqual(self.resolver.nameservers, ["1.1.1.1"])

    def test_otx_zero_results_still_reaches_shodan_and_certificates(self):
        finder = self._finder({"alpha.edu.tw": ["www.alpha.edu.tw"]}, otx_success=False)
        self.assertEqual(finder.run("*.alpha.edu.tw", skip_xlsx=True), [])
        self.shodan_http.assert_called_once()
        self.assertEqual(len(finder.certificate_provider.lookups), 1)
        self.assertEqual(self._states(), ({"alpha.edu.tw": "done"}, "completed"))

    def test_empty_discovery_still_checks_root_certificate(self):
        finder = self._finder({"alpha.edu.tw": []}, otx_success=False)
        finder.run("*.alpha.edu.tw", skip_xlsx=True)
        self.assertEqual(finder.certificate_provider.lookups,
                         [("alpha.edu.tw", ["alpha.edu.tw"])])
        self.assertEqual(self._states(), ({"alpha.edu.tw": "done"}, "completed"))

    def test_no_valid_certificates_completes_without_updating_timestamps(self):
        finder = self._finder({"alpha.edu.tw": ["www.alpha.edu.tw"]})
        finder.certificate_provider.active_names = set()
        finder.run("*.alpha.edu.tw", skip_xlsx=True)
        self.assertEqual(self._states(), ({"alpha.edu.tw": "done"}, "completed"))
        self.assertIsNone(self._checked_time("www.alpha.edu.tw"))

    def test_real_merklemap_provider_exhausted_retries_leave_target_failed(self):
        finder = self._finder({"alpha.edu.tw": ["www.alpha.edu.tw"]})
        search = Mock(status_code=200)
        search.json.return_value = {
            "count": 1, "results": [{"hostname": "www.alpha.edu.tw"}],
        }
        missing = Mock(status_code=404)
        errors = []
        for _ in range(3):
            response = Mock(status_code=502, headers={})
            response.raise_for_status.side_effect = requests.HTTPError("offline 502")
            errors.append(response)
        session = Mock(headers={})
        session.get.side_effect = [search, missing, *errors]
        provider = MerkleMapProvider(
            "offline-token", session=session, request_delay=0, sleeper=Mock(),
        )
        finder.certificate_provider = provider
        finder.certificate_validator.provider = provider

        finder.run("*.alpha.edu.tw", skip_xlsx=True)

        self.assertEqual(self._states(), ({"alpha.edu.tw": "failed"}, "failed"))
        self.assertEqual(provider.request_counts, {"search": 1, "certificates": 4})
        self.assertIsNone(self._checked_time("www.alpha.edu.tw"))

    def test_partial_failure_continues_other_roots_and_resume_only_retries_failed_root(self):
        discoveries = {"alpha.edu.tw": ["www.alpha.edu.tw"],
                       "beta.edu.tw": ["www.beta.edu.tw"]}
        finder = self._finder(discoveries)
        finder.certificate_provider.fail_roots.add("alpha.edu.tw")
        finder.run("*.alpha.edu.tw", skip_xlsx=True)
        self.assertEqual(self._states(),
                         ({"alpha.edu.tw": "failed", "beta.edu.tw": "done"}, "failed"))
        self.assertIsInstance(self._checked_time("www.alpha.edu.tw"), datetime)
        with db_session(self.db.SessionFactory) as session:
            target = session.execute(select(ScanTarget).where(ScanTarget.target == "alpha.edu.tw")).scalar_one()
            self.assertIn("offline timeout", target.error_message)

        resumed = self._finder(discoveries)
        resumed.run("*.alpha.edu.tw", resume=True)
        resumed.shodan_scanner.scan.assert_not_called()
        self.assertEqual([root for root, _ in resumed.certificate_provider.lookups], ["alpha.edu.tw"])
        self.assertEqual(self._states(),
                         ({"alpha.edu.tw": "done", "beta.edu.tw": "done"}, "completed"))

    def test_ctrl_c_during_certificate_keeps_target_running_and_resumable(self):
        discoveries = {"alpha.edu.tw": ["www.alpha.edu.tw"],
                       "beta.edu.tw": ["www.beta.edu.tw"]}
        finder = self._finder(discoveries)
        finder.certificate_provider.interrupt_root = "beta.edu.tw"
        with self.assertRaises(KeyboardInterrupt):
            finder.run("*.alpha.edu.tw", skip_xlsx=True)
        self.assertEqual(self._states(),
                         ({"alpha.edu.tw": "done", "beta.edu.tw": "running"}, "running"))

        resumed = self._finder(discoveries)
        resumed.run("*.alpha.edu.tw", resume=True)
        self.assertEqual([root for root, _ in resumed.certificate_provider.lookups], ["beta.edu.tw"])
        self.assertEqual(self._states(),
                         ({"alpha.edu.tw": "done", "beta.edu.tw": "done"}, "completed"))

    def test_area_school_root_is_preserved_and_overlapping_batches_do_not_repeat_lookups(self):
        self.db.get_all_area_domains = Mock(return_value={"tp.edu.tw"})
        finder = self._finder({
            "tp.edu.tw": ["stuinfo.taivs.tp.edu.tw"],
            "taivs.tp.edu.tw": ["stuinfo.taivs.tp.edu.tw"],
        })
        finder.run("*.edu.tw", skip_xlsx=True)
        self.assertIn(("taivs.tp.edu.tw", ["stuinfo.taivs.tp.edu.tw", "taivs.tp.edu.tw"]),
                      finder.certificate_provider.lookups)
        checked_hosts = [host for _, hosts in finder.certificate_provider.lookups for host in hosts]
        self.assertEqual(len(checked_hosts), len(set(checked_hosts)))
        self.assertEqual(self._states(),
                         ({"tp.edu.tw": "done", "taivs.tp.edu.tw": "done"}, "completed"))

    def test_missing_domain_is_a_failure_without_api_lookup(self):
        finder = self._finder({})
        result = finder.certificate_validator.validate_root_domain(
            "alpha.edu.tw", ["missing.alpha.edu.tw"],
        )
        self.assertIn("missing.alpha.edu.tw", result.failures)
        self.assertEqual(finder.certificate_provider.lookups, [])

    def test_save_method_uses_explicit_school_roots_and_check_time(self):
        hosts = ["www.ncku.edu.tw", "stuinfo.taivs.tp.edu.tw"]
        roots = ["ncku.edu.tw", "taivs.tp.edu.tw"]
        build_domain_hierarchy(self.db, hosts, roots)
        self.db.get_all_area_domains = Mock(
            side_effect=AssertionError("Area rules must come from the argument"),
        )
        finder = self._finder({})
        checked_at = datetime(2026, 10, 14, 12, 0)

        saved = finder._save_websites_by_storage_root(
            [Website(fqdn=host) for host in hosts],
            {"tp.edu.tw"},
            when_latest_otx_checked=checked_at,
        )

        self.assertEqual(saved, 2)
        with db_session(self.db.SessionFactory) as session:
            for host, root in zip(hosts, roots):
                domain = self.db._find_domain_by_fqdn(session, host)
                self.assertEqual(session.get(RootDomain, domain.root_id).name, root)
                self.assertEqual(domain.when_latest_otx_checked, checked_at)

    def test_database_write_failure_does_not_complete_target(self):
        finder = self._finder({"alpha.edu.tw": ["www.alpha.edu.tw"]})

        def remove_requested_domain(root, hosts):
            with db_session(self.db.SessionFactory) as session:
                domain = self.db._find_domain_by_fqdn(session, "www.alpha.edu.tw")
                session.execute(delete(Domain).where(Domain.id == domain.id))

        finder.certificate_provider.on_lookup = remove_requested_domain
        finder.run("*.alpha.edu.tw", skip_xlsx=True)
        self.assertEqual(self._states(), ({"alpha.edu.tw": "failed"}, "failed"))


if __name__ == "__main__":
    unittest.main()
