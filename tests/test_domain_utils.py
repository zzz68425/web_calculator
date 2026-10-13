"""Offline tests for explicit domain naming and storage-root rules."""

import unittest

from utils.domain import extract_root_domain, infer_storage_root


class DomainUtilsTests(unittest.TestCase):
    def test_extract_root_preserves_education_and_fallback_rules(self):
        cases = [
            ("stu.med.ncku.edu.tw", "ncku.edu.tw"),
            ("WWW.NCKU.EDU.TW", "ncku.edu.tw"),
            ("stuinfo.taivs.tp.edu.tw", "tp.edu.tw"),
            ("www.example.com", "example.com"),
            ("localhost", "localhost"),
        ]
        for domain, expected in cases:
            with self.subTest(domain=domain):
                self.assertEqual(extract_root_domain(domain), expected)

    def test_area_and_school_children_are_separate_storage_roots(self):
        cases = [
            ("tp.edu.tw", "tp.edu.tw"),
            ("taivs.tp.edu.tw", "taivs.tp.edu.tw"),
            ("stuinfo.taivs.tp.edu.tw", "taivs.tp.edu.tw"),
        ]
        for domain, expected in cases:
            with self.subTest(domain=domain):
                self.assertEqual(infer_storage_root(domain, {"tp.edu.tw"}), expected)

    def test_storage_root_normalizes_case_whitespace_and_trailing_dot(self):
        self.assertEqual(
            infer_storage_root("  STUINFO.TAIVS.TP.EDU.TW.  ", {"tp.edu.tw"}),
            "taivs.tp.edu.tw",
        )

    def test_area_rules_are_supplied_by_caller(self):
        domain = "stuinfo.taivs.tp.edu.tw"
        self.assertEqual(infer_storage_root(domain, set()), "tp.edu.tw")
        self.assertEqual(
            infer_storage_root(domain, {"tp.edu.tw"}), "taivs.tp.edu.tw",
        )

    def test_non_area_roots_do_not_pick_a_school_level(self):
        self.assertEqual(
            infer_storage_root("stu.med.ncku.edu.tw", {"tp.edu.tw"}),
            "ncku.edu.tw",
        )
        self.assertEqual(
            infer_storage_root("www.nottp.edu.tw", {"tp.edu.tw"}),
            "nottp.edu.tw",
        )


if __name__ == "__main__":
    unittest.main()
