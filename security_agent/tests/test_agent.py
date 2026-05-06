"""Tests for the security agent."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from security_agent.knowledge_base import KnowledgeBase
from security_agent.analyzer import Analyzer, Severity, Finding
from security_agent.reporter import ReportGenerator
from security_agent.agent import SecurityAgent


class TestKnowledgeBase(unittest.TestCase):
    def setUp(self):
        self.kb = KnowledgeBase()

    def test_cis_controls_loaded(self):
        controls = self.kb.list_cis_controls()
        self.assertGreater(len(controls), 0)

    def test_nist_controls_loaded(self):
        controls = self.kb.list_nist_controls()
        self.assertGreater(len(controls), 0)

    def test_cis_get_by_id(self):
        ctrl = self.kb.get_cis_control("CIS-OS-5.3")
        self.assertIsNotNone(ctrl)
        self.assertEqual(ctrl.id, "CIS-OS-5.3")
        self.assertIn("SSH", ctrl.title)

    def test_nist_get_by_id(self):
        ctrl = self.kb.get_nist_control("AC-6")
        self.assertIsNotNone(ctrl)
        self.assertEqual(ctrl.id, "AC-6")

    def test_nist_get_by_id_case_insensitive(self):
        ctrl = self.kb.get_nist_control("ac-6")
        self.assertIsNotNone(ctrl)

    def test_cis_list_by_level(self):
        l1 = self.kb.list_cis_controls(level=1)
        l2 = self.kb.list_cis_controls(level=2)
        self.assertTrue(all(c.level == 1 for c in l1))
        self.assertTrue(all(c.level == 2 for c in l2))

    def test_cis_list_by_category(self):
        controls = self.kb.list_cis_controls(category="network")
        self.assertTrue(all(c.category == "network" for c in controls))

    def test_nist_list_by_family(self):
        controls = self.kb.list_nist_controls(family="AC")
        self.assertTrue(all(c.family == "AC" for c in controls))

    def test_nist_list_by_baseline(self):
        controls = self.kb.list_nist_controls(baseline="HIGH")
        self.assertTrue(all("HIGH" in c.baseline for c in controls))

    def test_cis_search(self):
        results = self.kb.search_cis("ssh")
        self.assertGreater(len(results), 0)
        for c in results:
            self.assertTrue("ssh" in c.title.lower() or "ssh" in c.description.lower())

    def test_nist_search(self):
        results = self.kb.search_nist("authenticator")
        self.assertGreater(len(results), 0)

    def test_get_nist_families(self):
        families = self.kb.get_nist_families()
        self.assertGreater(len(families), 0)
        codes = [f[0] for f in families]
        self.assertIn("AC", codes)
        self.assertIn("AU", codes)

    def test_get_cis_categories(self):
        cats = self.kb.get_cis_categories()
        self.assertGreater(len(cats), 0)


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = Analyzer()

    def _secure_config(self):
        return {
            "ssh": {"permit_root_login": False, "protocol": 2, "permit_empty_passwords": False},
            "firewall": {"enabled": True, "default_policy": "DENY"},
            "password_policy": {
                "min_length": 14,
                "complexity_enabled": True,
                "max_age_days": 90,
                "lockout_enabled": True,
            },
            "mfa": {"enabled": True, "required_for_remote": True},
            "audit": {
                "auditd_installed": True,
                "auditd_enabled": True,
                "max_log_size_mb": 100,
                "log_protected": True,
                "log_permissions_correct": True,
                "logged_events": ["login", "sudo", "file_access"],
                "record_content_complete": True,
                "review_process_defined": True,
                "siem_configured": True,
                "remote_logging_enabled": True,
            },
            "encryption": {
                "tls_version": "1.2",
                "in_transit": True,
                "at_rest": True,
                "disk_encrypted": True,
            },
            "patch_management": {"current": True},
            "antivirus": {"installed": True, "definitions_current": True},
            "network": {
                "ip_forwarding": False,
                "icmp_broadcast_ignore": True,
                "ipv6_required": False,
                "ipv6_disabled": True,
                "boundary_protection": True,
                "dmz": True,
                "dos_protection": True,
                "unused_ports_closed": True,
            },
            "file_integrity_monitoring": {"enabled": True, "aide_installed": True},
            "policies": {
                "access_control": True,
                "audit": True,
                "configuration_management": True,
                "identification_authentication": True,
                "incident_response": True,
                "risk_assessment": True,
            },
            "vulnerability_management": {
                "scanning_enabled": True,
                "scan_frequency": "weekly",
                "risk_assessment_done": True,
                "risk_assessment_current": True,
            },
            "unique_user_ids": True,
            "xwindow_installed": False,
            "ntp": {"enabled": True},
            "syslog": {"configured": True, "log_permissions_correct": True},
            "ids_ips": {"enabled": True},
            "monitoring": {"alerts_enabled": True},
            "access_control": {
                "least_privilege": True,
                "privileged_review": True,
                "account_management": True,
                "account_review": True,
                "enforcement_configured": True,
                "inactive_accounts_disabled": True,
                "external_auth": True,
            },
            "remote_access": {"policy_defined": True, "vpn_enabled": True},
            "bootloader": {"permissions_correct": True},
            "services": {"minimal_install": True},
            "configuration_management": {
                "baseline_documented": True,
                "hardened": True,
                "cis_applied": True,
            },
            "database": {"default_password_changed": True},
            "incident_response": {"process_defined": True, "team_defined": True},
        }

    def test_analyze_no_findings_for_secure_config(self):
        config = self._secure_config()
        findings = self.analyzer.analyze(config)
        self.assertEqual(findings, [], f"Expected no findings, got: {findings}")

    def test_analyze_empty_config_has_findings(self):
        findings = self.analyzer.analyze({})
        self.assertGreater(len(findings), 0)

    def test_analyze_framework_filter_cis_only(self):
        findings = self.analyzer.analyze({}, frameworks=["CIS"])
        self.assertTrue(all(f.framework == "CIS" for f in findings))

    def test_analyze_framework_filter_nist_only(self):
        findings = self.analyzer.analyze({}, frameworks=["NIST"])
        self.assertTrue(all(f.framework == "NIST" for f in findings))

    def test_ssh_root_login_finding(self):
        config = self._secure_config()
        config["ssh"]["permit_root_login"] = True
        findings = self.analyzer.analyze(config, frameworks=["CIS"])
        ids = [f.control_id for f in findings]
        self.assertIn("CIS-OS-5.3", ids)

    def test_findings_sorted_by_severity(self):
        findings = self.analyzer.analyze({})
        severity_order = [s.value for s in Severity]
        for i in range(len(findings) - 1):
            self.assertLessEqual(
                severity_order.index(findings[i].severity.value),
                severity_order.index(findings[i + 1].severity.value),
            )

    def test_findings_contain_remediation(self):
        findings = self.analyzer.analyze({})
        for f in findings:
            self.assertIsInstance(f.remediation, str)
            self.assertGreater(len(f.remediation), 0)


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.reporter = ReportGenerator()
        self.analyzer = Analyzer()
        self.findings = self.analyzer.analyze({})

    def test_text_report_contains_key_sections(self):
        report = self.reporter.generate_text(self.findings)
        self.assertIn("EXECUTIVE SUMMARY", report)
        self.assertIn("Total Findings", report)
        self.assertIn("Risk Score", report)

    def test_json_report_is_valid_json(self):
        report = self.reporter.generate_json(self.findings)
        data = json.loads(report)
        self.assertIn("report", data)
        self.assertIn("findings", data["report"])
        self.assertIn("summary", data["report"])

    def test_json_report_findings_count_matches(self):
        report = self.reporter.generate_json(self.findings)
        data = json.loads(report)
        self.assertEqual(data["report"]["summary"]["total"], len(self.findings))

    def test_text_report_no_findings(self):
        report = self.reporter.generate_text([])
        self.assertIn("No findings", report)


class TestSecurityAgent(unittest.TestCase):
    def setUp(self):
        self.agent = SecurityAgent()

    def test_help_command(self):
        response = self.agent.chat("help")
        self.assertIn("CIS Commands", response)
        self.assertIn("NIST Commands", response)

    def test_unknown_command(self):
        response = self.agent.chat("foobar")
        self.assertIn("Unknown command", response)

    def test_cis_categories(self):
        response = self.agent.chat("cis categories")
        self.assertIn("network", response.lower())

    def test_cis_list(self):
        response = self.agent.chat("cis list")
        self.assertIn("CIS-OS-5.3", response)

    def test_cis_list_level_1(self):
        response = self.agent.chat("cis list --level 1")
        self.assertIn("CIS Controls", response)

    def test_cis_get(self):
        response = self.agent.chat("cis get CIS-OS-5.3")
        self.assertIn("SSH root login", response)

    def test_cis_get_not_found(self):
        response = self.agent.chat("cis get CIS-INVALID")
        self.assertIn("not found", response)

    def test_cis_search(self):
        response = self.agent.chat("cis search ssh")
        self.assertIn("CIS-OS-5.3", response)

    def test_nist_families(self):
        response = self.agent.chat("nist families")
        self.assertIn("Access Control", response)

    def test_nist_list(self):
        response = self.agent.chat("nist list")
        self.assertIn("AC-6", response)

    def test_nist_list_family(self):
        response = self.agent.chat("nist list --family AC")
        self.assertIn("AC-6", response)

    def test_nist_get(self):
        response = self.agent.chat("nist get AC-6")
        self.assertIn("Least Privilege", response)

    def test_nist_search(self):
        response = self.agent.chat("nist search encryption")
        self.assertGreater(len(response), 0)

    def test_analyze_missing_file(self):
        response = self.agent.chat("analyze /tmp/nonexistent_file_xyz.json")
        self.assertIn("not found", response.lower())

    def test_analyze_valid_file(self):
        config = {
            "ssh": {"permit_root_login": False, "protocol": 2, "permit_empty_passwords": False}
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(config, f)
            tmp_path = f.name
        try:
            response = self.agent.chat(f"analyze {tmp_path}")
            self.assertIn("Security Assessment Report", response)
        finally:
            os.unlink(tmp_path)

    def test_analyze_json_output(self):
        config = {}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(config, f)
            tmp_path = f.name
        try:
            response = self.agent.chat(f"analyze {tmp_path} --output json")
            data = json.loads(response)
            self.assertIn("report", data)
        finally:
            os.unlink(tmp_path)

    def test_quit_command(self):
        response = self.agent.chat("quit")
        self.assertIn("Goodbye", response)


if __name__ == "__main__":
    unittest.main()
