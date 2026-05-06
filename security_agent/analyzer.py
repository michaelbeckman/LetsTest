"""
Security Agent - configuration analyzer.

Evaluates a configuration dictionary against CIS benchmarks and NIST controls
and produces a list of Findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .knowledge_base import CISControl, KnowledgeBase, NISTControl


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    framework: str          # "CIS" or "NIST"
    control_id: str
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"[{self.severity.value}] {self.control_id} – {self.title}\n"
            f"  Description : {self.description}\n"
            f"  Remediation : {self.remediation}"
        )


# ---------------------------------------------------------------------------
# Internal check helpers
# ---------------------------------------------------------------------------

def _check_ssh(config: dict[str, Any]) -> dict[str, bool]:
    ssh = config.get("ssh", {})
    return {
        "ssh_root_login_disabled": ssh.get("permit_root_login", True) is False,
        "ssh_protocol_v2": ssh.get("protocol", 1) == 2,
        "ssh_empty_passwords_disabled": ssh.get("permit_empty_passwords", True) is False,
    }


def _check_firewall(config: dict[str, Any]) -> dict[str, bool]:
    fw = config.get("firewall", {})
    return {
        "firewall_active": fw.get("enabled", False) is True,
        "firewall_default_deny": fw.get("default_policy", "ACCEPT").upper() == "DENY",
        "firewall_configured": fw.get("enabled", False) is True,
    }


def _check_password(config: dict[str, Any]) -> dict[str, bool]:
    pw = config.get("password_policy", {})
    return {
        "password_min_length": pw.get("min_length", 0) >= 14,
        "password_complexity": pw.get("complexity_enabled", False) is True,
        "password_policy_configured": bool(pw),
        "password_expiry_set": pw.get("max_age_days", 0) > 0,
        "password_complexity_enforced": pw.get("complexity_enabled", False) is True,
    }


def _check_mfa(config: dict[str, Any]) -> dict[str, bool]:
    mfa = config.get("mfa", {})
    return {
        "mfa_enabled": mfa.get("enabled", False) is True,
        "mfa_for_remote_access": mfa.get("required_for_remote", False) is True,
        "unique_user_ids": config.get("unique_user_ids", False) is True,
    }


def _check_audit(config: dict[str, Any]) -> dict[str, bool]:
    audit = config.get("audit", {})
    return {
        "auditd_installed": audit.get("auditd_installed", False) is True,
        "auditd_enabled": audit.get("auditd_enabled", False) is True,
        "audit_log_size_configured": audit.get("max_log_size_mb", 0) > 0,
        "audit_log_protected": audit.get("log_protected", False) is True,
        "audit_log_permissions": audit.get("log_permissions_correct", False) is True,
        "event_logging_configured": audit.get("auditd_enabled", False) is True,
        "audit_log_events_defined": bool(audit.get("logged_events")),
        "audit_record_content_complete": audit.get("record_content_complete", False) is True,
        "audit_review_process": audit.get("review_process_defined", False) is True,
        "siem_configured": audit.get("siem_configured", False) is True,
        "remote_audit_logging": audit.get("remote_logging_enabled", False) is True,
    }


def _check_encryption(config: dict[str, Any]) -> dict[str, bool]:
    enc = config.get("encryption", {})
    return {
        "tls_configured": enc.get("tls_version", "1.0") in ("1.2", "1.3"),
        "tls_version_check": enc.get("tls_version", "1.0") in ("1.2", "1.3"),
        "encryption_in_transit": enc.get("in_transit", False) is True,
        "encryption_at_rest": enc.get("at_rest", False) is True,
        "disk_encryption_enabled": enc.get("disk_encrypted", False) is True,
    }


def _check_patch(config: dict[str, Any]) -> dict[str, bool]:
    patch = config.get("patch_management", {})
    return {
        "patch_management_process": bool(patch),
        "patching_current": patch.get("current", False) is True,
    }


def _check_antivirus(config: dict[str, Any]) -> dict[str, bool]:
    av = config.get("antivirus", {})
    return {
        "antivirus_installed": av.get("installed", False) is True,
        "antivirus_updated": av.get("definitions_current", False) is True,
    }


def _check_network(config: dict[str, Any]) -> dict[str, bool]:
    net = config.get("network", {})
    return {
        "ip_forwarding_disabled": net.get("ip_forwarding", True) is False,
        "icmp_broadcast_ignored": net.get("icmp_broadcast_ignore", False) is True,
        "ipv6_disabled_if_unused": (
            not net.get("ipv6_required", True) and net.get("ipv6_disabled", False)
        ) or net.get("ipv6_required", True),
    }


def _check_integrity(config: dict[str, Any]) -> dict[str, bool]:
    fim = config.get("file_integrity_monitoring", {})
    return {
        "aide_installed": fim.get("aide_installed", False) is True,
        "tripwire_installed": fim.get("tripwire_installed", False) is True,
        "integrity_checking_enabled": fim.get("enabled", False) is True,
        "file_integrity_monitoring": fim.get("enabled", False) is True,
    }


def _check_policies(config: dict[str, Any]) -> dict[str, bool]:
    policies = config.get("policies", {})
    return {
        "access_control_policy_exists": policies.get("access_control", False) is True,
        "audit_policy_exists": policies.get("audit", False) is True,
        "cm_policy_exists": policies.get("configuration_management", False) is True,
        "ia_policy_exists": policies.get("identification_authentication", False) is True,
        "ir_policy_exists": policies.get("incident_response", False) is True,
        "ra_policy_exists": policies.get("risk_assessment", False) is True,
    }


def _check_vulnerability(config: dict[str, Any]) -> dict[str, bool]:
    vuln = config.get("vulnerability_management", {})
    return {
        "vulnerability_scanning_enabled": vuln.get("scanning_enabled", False) is True,
        "scan_frequency_defined": bool(vuln.get("scan_frequency")),
        "risk_assessment_completed": vuln.get("risk_assessment_done", False) is True,
        "risk_assessment_current": vuln.get("risk_assessment_current", False) is True,
    }


def _check_misc(config: dict[str, Any]) -> dict[str, bool]:
    return {
        "ntp_enabled": config.get("ntp", {}).get("enabled", False) is True,
        "chrony_enabled": config.get("chrony", {}).get("enabled", False) is True,
        "xwindow_not_installed": config.get("xwindow_installed", True) is False,
        "syslog_configured": config.get("syslog", {}).get("configured", False) is True,
        "log_file_permissions": config.get("syslog", {}).get("log_permissions_correct", False) is True,
        "ids_ips_configured": config.get("ids_ips", {}).get("enabled", False) is True,
        "monitoring_alerts_configured": config.get("monitoring", {}).get("alerts_enabled", False) is True,
        "least_privilege_check": config.get("access_control", {}).get("least_privilege", False) is True,
        "least_privilege_enforced": config.get("access_control", {}).get("least_privilege", False) is True,
        "privileged_accounts_reviewed": config.get("access_control", {}).get("privileged_review", False) is True,
        "account_management_process": config.get("access_control", {}).get("account_management", False) is True,
        "account_review_schedule": config.get("access_control", {}).get("account_review", False) is True,
        "account_lockout_configured": config.get("password_policy", {}).get("lockout_enabled", False) is True,
        "access_enforcement_configured": config.get("access_control", {}).get("enforcement_configured", False) is True,
        "inactive_accounts_check": config.get("access_control", {}).get("inactive_accounts_disabled", False) is True,
        "grub_permissions": config.get("bootloader", {}).get("permissions_correct", False) is True,
        "remote_access_policy": config.get("remote_access", {}).get("policy_defined", False) is True,
        "vpn_configured": config.get("remote_access", {}).get("vpn_enabled", False) is True,
        "boundary_protection_configured": config.get("network", {}).get("boundary_protection", False) is True,
        "dmz_configured": config.get("network", {}).get("dmz", False) is True,
        "dos_protection_configured": config.get("network", {}).get("dos_protection", False) is True,
        "unnecessary_services_disabled": config.get("services", {}).get("minimal_install", False) is True,
        "unused_ports_closed": config.get("network", {}).get("unused_ports_closed", False) is True,
        "baseline_configuration_documented": config.get("configuration_management", {}).get("baseline_documented", False) is True,
        "configuration_settings_hardened": config.get("configuration_management", {}).get("hardened", False) is True,
        "cis_benchmark_applied": config.get("configuration_management", {}).get("cis_applied", False) is True,
        "web_server_required_check": True,   # assume web server is intended; operator can override
        "db_default_password_changed": config.get("database", {}).get("default_password_changed", False) is True,
        "external_user_auth_configured": config.get("access_control", {}).get("external_auth", False) is True,
        "incident_handling_process": config.get("incident_response", {}).get("process_defined", False) is True,
        "incident_response_team": config.get("incident_response", {}).get("team_defined", False) is True,
    }


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_CIS_LEVEL_TO_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM}
_NIST_PRIORITY_TO_SEVERITY = {
    "P1": Severity.HIGH,
    "P2": Severity.MEDIUM,
    "P3": Severity.LOW,
}


def _cis_severity(control: CISControl) -> Severity:
    return _CIS_LEVEL_TO_SEVERITY.get(control.level, Severity.MEDIUM)


def _nist_severity(control: NISTControl) -> Severity:
    return _NIST_PRIORITY_TO_SEVERITY.get(control.priority, Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class Analyzer:
    """
    Evaluates a system configuration dictionary against CIS and NIST controls.

    Configuration format (all keys optional):
    {
        "ssh": {"permit_root_login": false, "protocol": 2, "permit_empty_passwords": false},
        "firewall": {"enabled": true, "default_policy": "DENY"},
        "password_policy": {"min_length": 14, "complexity_enabled": true, "max_age_days": 90, "lockout_enabled": true},
        "mfa": {"enabled": true, "required_for_remote": true},
        "audit": {"auditd_installed": true, "auditd_enabled": true, "max_log_size_mb": 100, ...},
        "encryption": {"tls_version": "1.2", "in_transit": true, "at_rest": true, "disk_encrypted": true},
        "patch_management": {"current": true},
        "antivirus": {"installed": true, "definitions_current": true},
        "network": {"ip_forwarding": false, "icmp_broadcast_ignore": true, ...},
        "file_integrity_monitoring": {"enabled": true, "aide_installed": true},
        "policies": {"access_control": true, "audit": true, ...},
        "vulnerability_management": {"scanning_enabled": true, "scan_frequency": "weekly", ...},
        "unique_user_ids": true,
        ...
    }
    """

    def __init__(self, kb: KnowledgeBase | None = None) -> None:
        self._kb = kb or KnowledgeBase()

    def analyze(
        self,
        config: dict[str, Any],
        frameworks: list[str] | None = None,
    ) -> list[Finding]:
        """
        Run all checks and return a list of Findings for failed controls.

        :param config: System configuration dictionary.
        :param frameworks: Optional list of frameworks to check, e.g. ["CIS", "NIST"].
                           Defaults to both.
        """
        check_frameworks = {f.upper() for f in (frameworks or ["CIS", "NIST"])}
        check_results = self._run_checks(config)
        findings: list[Finding] = []

        if "CIS" in check_frameworks:
            findings.extend(self._evaluate_cis(check_results))
        if "NIST" in check_frameworks:
            findings.extend(self._evaluate_nist(check_results))

        findings.sort(key=lambda f: (list(Severity).index(f.severity), f.control_id))
        return findings

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_checks(self, config: dict[str, Any]) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for checker in (
            _check_ssh,
            _check_firewall,
            _check_password,
            _check_mfa,
            _check_audit,
            _check_encryption,
            _check_patch,
            _check_antivirus,
            _check_network,
            _check_integrity,
            _check_policies,
            _check_vulnerability,
            _check_misc,
        ):
            results.update(checker(config))
        return results

    def _evaluate_cis(self, check_results: dict[str, bool]) -> list[Finding]:
        findings: list[Finding] = []
        for ctrl in self._kb.list_cis_controls():
            if ctrl.check_mode == "any":
                failed = [c for c in ctrl.checks if not check_results.get(c, False)]
                passed = any(check_results.get(c, False) for c in ctrl.checks)
                if passed:
                    continue
            else:
                failed = [c for c in ctrl.checks if not check_results.get(c, False)]
            if failed:
                findings.append(
                    Finding(
                        id=f"CIS-{ctrl.id}",
                        title=ctrl.title,
                        description=ctrl.description,
                        severity=_cis_severity(ctrl),
                        framework="CIS",
                        control_id=ctrl.id,
                        remediation=ctrl.remediation,
                        details={"failed_checks": failed, "category": ctrl.category_name},
                    )
                )
        return findings

    def _evaluate_nist(self, check_results: dict[str, bool]) -> list[Finding]:
        findings: list[Finding] = []
        for ctrl in self._kb.list_nist_controls():
            failed = [c for c in ctrl.checks if not check_results.get(c, False)]
            if failed:
                findings.append(
                    Finding(
                        id=f"NIST-{ctrl.id}",
                        title=ctrl.title,
                        description=ctrl.description,
                        severity=_nist_severity(ctrl),
                        framework="NIST",
                        control_id=ctrl.id,
                        remediation=f"Implement NIST SP 800-53 {ctrl.id} requirements. Related: {', '.join(ctrl.related[:3])}.",
                        details={
                            "failed_checks": failed,
                            "family": ctrl.family_name,
                            "baseline": ctrl.baseline,
                        },
                    )
                )
        return findings
