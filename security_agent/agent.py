"""
Security Agent - interactive conversational interface.

Allows users to query CIS benchmarks, NIST controls, and run analyses
through a simple text-based chat loop.
"""

from __future__ import annotations

import textwrap
from typing import Any

from .analyzer import Analyzer, Severity
from .knowledge_base import KnowledgeBase
from .reporter import ReportGenerator


_HELP = textwrap.dedent("""\
    Security Agent – Available Commands
    ────────────────────────────────────────────────────────────────────
    help                         Show this help message
    quit / exit                  Exit the agent

    CIS Commands:
      cis list                   List all CIS benchmark controls
      cis list --level 1         List Level-1 CIS controls
      cis list --level 2         List Level-2 CIS controls
      cis list --category <cat>  List CIS controls by category
      cis categories             Show available CIS categories
      cis get <ID>               Get details for a specific CIS control (e.g. CIS-OS-5.3)
      cis search <keyword>       Search CIS controls by keyword

    NIST Commands:
      nist list                  List all NIST SP 800-53 controls
      nist list --family <fam>   List NIST controls by family code (e.g. AC, AU, SC)
      nist list --baseline <lvl> List NIST controls by baseline (LOW, MODERATE, HIGH)
      nist families              Show available NIST control families
      nist get <ID>              Get details for a specific NIST control (e.g. AC-6)
      nist search <keyword>      Search NIST controls by keyword

    Analysis Commands:
      analyze <json-file>        Analyze a config JSON file against CIS and NIST
      analyze <json-file> --frameworks CIS,NIST
                                 Limit analysis to specific frameworks
      analyze <json-file> --output text|json
                                 Choose report format (default: text)
    ────────────────────────────────────────────────────────────────────
""")


class SecurityAgent:
    """Interactive security agent with CIS and NIST knowledge."""

    def __init__(self) -> None:
        self._kb = KnowledgeBase()
        self._analyzer = Analyzer(self._kb)
        self._reporter = ReportGenerator()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def chat(self, user_input: str) -> str:
        """Process a single command string and return a response string."""
        tokens = user_input.strip().split()
        if not tokens:
            return ""
        cmd = tokens[0].lower()

        if cmd in ("help", "?"):
            return _HELP
        if cmd in ("quit", "exit"):
            return "Goodbye. Stay secure! 🔒"
        if cmd == "cis":
            return self._handle_cis(tokens[1:])
        if cmd == "nist":
            return self._handle_nist(tokens[1:])
        if cmd == "analyze":
            return self._handle_analyze(tokens[1:])

        return (
            f"Unknown command: '{cmd}'. "
            "Type 'help' for a list of available commands."
        )

    def run(self) -> None:
        """Start the interactive REPL."""
        print("=" * 60)
        print("  Security Agent v1.0")
        print("  CIS Benchmarks | NIST SP 800-53")
        print("  Type 'help' for available commands, 'quit' to exit.")
        print("=" * 60)
        while True:
            try:
                user_input = input("\nsecurity-agent> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nGoodbye. Stay secure! 🔒")
                break
            if not user_input:
                continue
            response = self.chat(user_input)
            print(response)
            if response == "Goodbye. Stay secure! 🔒":
                break

    # ------------------------------------------------------------------
    # CIS handlers
    # ------------------------------------------------------------------

    def _handle_cis(self, args: list[str]) -> str:
        if not args:
            return "Usage: cis <list|categories|get|search> [options]"

        sub = args[0].lower()

        if sub == "categories":
            cats = self._kb.get_cis_categories()
            lines = ["CIS Benchmark Categories:", ""]
            for key, name in cats:
                lines.append(f"  {key:<25} {name}")
            return "\n".join(lines)

        if sub == "list":
            level: int | None = None
            category: str | None = None
            i = 1
            while i < len(args):
                if args[i] == "--level" and i + 1 < len(args):
                    try:
                        level = int(args[i + 1])
                    except ValueError:
                        return f"Invalid level: {args[i + 1]}"
                    i += 2
                elif args[i] == "--category" and i + 1 < len(args):
                    category = args[i + 1]
                    i += 2
                else:
                    i += 1
            controls = self._kb.list_cis_controls(category=category, level=level)
            if not controls:
                return "No CIS controls found matching the given filters."
            lines = [f"CIS Controls ({len(controls)} found):", ""]
            for c in controls:
                lines.append(f"  {c.id:<15} [L{c.level}] {c.title}")
            return "\n".join(lines)

        if sub == "get":
            if len(args) < 2:
                return "Usage: cis get <control-id>"
            ctrl = self._kb.get_cis_control(args[1])
            if not ctrl:
                return f"CIS control '{args[1]}' not found."
            return self._format_cis(ctrl)

        if sub == "search":
            if len(args) < 2:
                return "Usage: cis search <keyword>"
            keyword = " ".join(args[1:])
            results = self._kb.search_cis(keyword)
            if not results:
                return f"No CIS controls found matching '{keyword}'."
            lines = [f"CIS Search results for '{keyword}' ({len(results)} found):", ""]
            for c in results:
                lines.append(f"  {c.id:<15} [L{c.level}] {c.title}")
            return "\n".join(lines)

        return f"Unknown CIS subcommand: '{sub}'. Try 'cis list', 'cis get', 'cis search', 'cis categories'."

    def _format_cis(self, ctrl: Any) -> str:
        lines = [
            f"CIS Control: {ctrl.id}",
            "─" * 50,
            f"Title      : {ctrl.title}",
            f"Category   : {ctrl.category_name}",
            f"Level      : {ctrl.level}",
            f"Description:",
            f"  {ctrl.description}",
            f"Remediation:",
            f"  {ctrl.remediation}",
            f"Checks     : {', '.join(ctrl.checks)}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # NIST handlers
    # ------------------------------------------------------------------

    def _handle_nist(self, args: list[str]) -> str:
        if not args:
            return "Usage: nist <list|families|get|search> [options]"

        sub = args[0].lower()

        if sub == "families":
            families = self._kb.get_nist_families()
            lines = ["NIST SP 800-53 Control Families:", ""]
            for code, name in families:
                lines.append(f"  {code:<10} {name}")
            return "\n".join(lines)

        if sub == "list":
            family: str | None = None
            baseline: str | None = None
            i = 1
            while i < len(args):
                if args[i] == "--family" and i + 1 < len(args):
                    family = args[i + 1]
                    i += 2
                elif args[i] == "--baseline" and i + 1 < len(args):
                    baseline = args[i + 1]
                    i += 2
                else:
                    i += 1
            controls = self._kb.list_nist_controls(family=family, baseline=baseline)
            if not controls:
                return "No NIST controls found matching the given filters."
            lines = [f"NIST Controls ({len(controls)} found):", ""]
            for c in controls:
                baselines = "/".join(b[0] for b in c.baseline)  # L/M/H abbreviations
                lines.append(f"  {c.id:<10} [{c.priority}] [{baselines}] {c.title}")
            return "\n".join(lines)

        if sub == "get":
            if len(args) < 2:
                return "Usage: nist get <control-id>"
            ctrl = self._kb.get_nist_control(args[1])
            if not ctrl:
                return f"NIST control '{args[1]}' not found."
            return self._format_nist(ctrl)

        if sub == "search":
            if len(args) < 2:
                return "Usage: nist search <keyword>"
            keyword = " ".join(args[1:])
            results = self._kb.search_nist(keyword)
            if not results:
                return f"No NIST controls found matching '{keyword}'."
            lines = [f"NIST Search results for '{keyword}' ({len(results)} found):", ""]
            for c in results:
                lines.append(f"  {c.id:<10} [{c.priority}] {c.title}")
            return "\n".join(lines)

        return f"Unknown NIST subcommand: '{sub}'. Try 'nist list', 'nist get', 'nist search', 'nist families'."

    def _format_nist(self, ctrl: Any) -> str:
        lines = [
            f"NIST Control: {ctrl.id}",
            "─" * 50,
            f"Title      : {ctrl.title}",
            f"Family     : {ctrl.family_name} ({ctrl.family})",
            f"Priority   : {ctrl.priority}",
            f"Baseline   : {', '.join(ctrl.baseline)}",
            f"Description:",
            f"  {ctrl.description}",
            f"Related    : {', '.join(ctrl.related)}",
            f"Checks     : {', '.join(ctrl.checks)}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Analysis handler
    # ------------------------------------------------------------------

    def _handle_analyze(self, args: list[str]) -> str:
        if not args:
            return "Usage: analyze <config-json-file> [--frameworks CIS,NIST] [--output text|json]"

        import json
        import os

        filepath = args[0]
        frameworks: list[str] | None = None
        output_format = "text"
        system_name = os.path.basename(filepath)

        i = 1
        while i < len(args):
            if args[i] == "--frameworks" and i + 1 < len(args):
                frameworks = [f.strip() for f in args[i + 1].split(",")]
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                output_format = args[i + 1].lower()
                i += 2
            else:
                i += 1

        try:
            with open(filepath, encoding="utf-8") as f:
                config: dict[str, Any] = json.load(f)
        except FileNotFoundError:
            return f"File not found: {filepath}"
        except json.JSONDecodeError as exc:
            return f"Invalid JSON in '{filepath}': {exc}"

        findings = self._analyzer.analyze(config, frameworks=frameworks)

        if output_format == "json":
            return self._reporter.generate_json(findings, system_name=system_name)
        return self._reporter.generate_text(findings, system_name=system_name)
