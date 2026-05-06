# Security Agent

A Python-based security agent that embeds knowledge of **CIS Benchmarks** and
**NIST SP 800-53** controls and can evaluate system configurations against them.

---

## Features

| Feature | Details |
|---------|---------|
| **CIS Benchmarks** | Level 1 & Level 2 controls across OS hardening, network, application, access control, and logging categories |
| **NIST SP 800-53 Rev 5** | Controls from AC, AU, CM, IA, IR, RA, SC, and SI families |
| **Configuration Analyzer** | Evaluates a JSON config and produces severity-ranked findings with remediation steps |
| **Report Generation** | Human-readable text reports and structured JSON output |
| **Interactive CLI** | REPL interface for querying controls, searching, and running analyses |

---

## Directory Structure

```
security_agent/
├── __init__.py
├── __main__.py          # CLI entry point
├── agent.py             # Interactive agent / REPL
├── analyzer.py          # Configuration analyzer
├── knowledge_base.py    # Loads CIS & NIST control data
├── reporter.py          # Report generation (text / JSON)
├── data/
│   ├── cis_benchmarks.json   # CIS control definitions
│   └── nist_controls.json    # NIST SP 800-53 control definitions
└── tests/
    └── test_agent.py    # Unit tests (41 tests)
```

---

## Usage

### Interactive mode

```bash
python -m security_agent
# or
python -m security_agent --interactive
```

### Single command mode

```bash
# List all CIS Level-1 controls
python -m security_agent cis list --level 1

# Get details for a specific CIS control
python -m security_agent cis get CIS-OS-5.3

# Search CIS controls by keyword
python -m security_agent cis search firewall

# List NIST controls in the Access Control family
python -m security_agent nist list --family AC

# Get details for a NIST control
python -m security_agent nist get AC-6

# Analyze a system configuration file
python -m security_agent analyze config.json

# Analyze with JSON output
python -m security_agent analyze config.json --output json

# Analyze against CIS only
python -m security_agent analyze config.json --frameworks CIS
```

---

## Configuration File Format

The analyzer accepts a JSON file describing the system's security posture.
All keys are optional — missing keys are treated as "not configured" (failing).

```json
{
  "ssh": {
    "permit_root_login": false,
    "protocol": 2,
    "permit_empty_passwords": false
  },
  "firewall": {
    "enabled": true,
    "default_policy": "DENY"
  },
  "password_policy": {
    "min_length": 14,
    "complexity_enabled": true,
    "max_age_days": 90,
    "lockout_enabled": true
  },
  "mfa": {
    "enabled": true,
    "required_for_remote": true
  },
  "audit": {
    "auditd_installed": true,
    "auditd_enabled": true,
    "max_log_size_mb": 100,
    "log_protected": true,
    "log_permissions_correct": true,
    "logged_events": ["login", "sudo", "file_access"],
    "record_content_complete": true,
    "review_process_defined": true,
    "siem_configured": true,
    "remote_logging_enabled": true
  },
  "encryption": {
    "tls_version": "1.2",
    "in_transit": true,
    "at_rest": true,
    "disk_encrypted": true
  },
  "patch_management": { "current": true },
  "antivirus": { "installed": true, "definitions_current": true },
  "network": {
    "ip_forwarding": false,
    "icmp_broadcast_ignore": true,
    "boundary_protection": true,
    "dmz": true,
    "dos_protection": true,
    "unused_ports_closed": true
  },
  "file_integrity_monitoring": {
    "enabled": true,
    "aide_installed": true
  },
  "policies": {
    "access_control": true,
    "audit": true,
    "configuration_management": true,
    "identification_authentication": true,
    "incident_response": true,
    "risk_assessment": true
  },
  "vulnerability_management": {
    "scanning_enabled": true,
    "scan_frequency": "weekly",
    "risk_assessment_done": true,
    "risk_assessment_current": true
  }
}
```

---

## Sample Report Output

```
======================================================================
  Security Assessment Report
  System : my-server.json
  Date   : 2026-05-06 18:00:00 UTC
======================================================================

EXECUTIVE SUMMARY
----------------------------------------
Total Findings : 4
  CIS Findings : 2
  NIST Findings: 2

  HIGH      : 3
  MEDIUM    : 1

Risk Score : 17/100  (LOW)

──────────────────────────────────────────────────────────────────────
  HIGH SEVERITY FINDINGS  (3)
──────────────────────────────────────────────────────────────────────

  [CIS] CIS-OS-5.3
  Title      : Ensure SSH root login is disabled
  Description: The PermitRootLogin parameter specifies if the root user can log in using ssh.
  Remediation: Set PermitRootLogin no in /etc/ssh/sshd_config
...
```

---

## Running Tests

```bash
python -m unittest security_agent.tests.test_agent -v
```

---

## Frameworks Covered

### CIS Benchmarks Categories
| Category | Controls |
|----------|---------|
| Operating System Hardening | Filesystem integrity, bootloader, time sync, X Window, network, auditing, passwords, SSH |
| Network Security | Firewall, default deny policy, IPv6 |
| Application Security | Web server, TLS version, database defaults |
| Access Control | MFA, least privilege, inactive accounts |
| Logging and Monitoring | Syslog, log permissions, remote audit logging |

### NIST SP 800-53 Rev 5 Families
| Family | Controls |
|--------|---------|
| AC – Access Control | AC-1 through AC-17 (account mgmt, least privilege, remote access) |
| AU – Audit & Accountability | AU-1 through AU-9 (event logging, record content, protection) |
| CM – Configuration Management | CM-1 through CM-7 (baselines, settings, least functionality) |
| IA – Identification & Authentication | IA-1 through IA-8 (unique IDs, MFA, authenticator mgmt) |
| IR – Incident Response | IR-1, IR-4 (policy, incident handling) |
| RA – Risk Assessment | RA-1, RA-3, RA-5 (risk assessment, vulnerability scanning) |
| SC – System & Communications Protection | SC-5, SC-7, SC-8, SC-28 (DoS, boundary, TLS, encryption at rest) |
| SI – System & Information Integrity | SI-2, SI-3, SI-4, SI-7 (patching, AV, monitoring, integrity) |
