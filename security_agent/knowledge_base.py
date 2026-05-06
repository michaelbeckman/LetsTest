"""
Security Agent - knowledge base loader for CIS benchmarks and NIST SP 800-53 controls.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


@dataclass
class CISControl:
    id: str
    title: str
    description: str
    level: int
    checks: list[str]
    remediation: str
    category: str
    category_name: str
    check_mode: str = "all"   # "all" = all checks must pass; "any" = at least one must pass


@dataclass
class NISTControl:
    id: str
    title: str
    description: str
    priority: str
    baseline: list[str]
    checks: list[str]
    related: list[str]
    family: str
    family_name: str


class KnowledgeBase:
    """Loads and indexes CIS benchmarks and NIST SP 800-53 controls."""

    def __init__(self) -> None:
        self._cis_controls: dict[str, CISControl] = {}
        self._nist_controls: dict[str, NISTControl] = {}
        self._load()

    def _load(self) -> None:
        cis_path = os.path.join(_DATA_DIR, "cis_benchmarks.json")
        nist_path = os.path.join(_DATA_DIR, "nist_controls.json")

        with open(cis_path, encoding="utf-8") as f:
            cis_data: dict[str, Any] = json.load(f)

        for cat_key, cat in cis_data["categories"].items():
            for ctrl in cat["controls"]:
                obj = CISControl(
                    id=ctrl["id"],
                    title=ctrl["title"],
                    description=ctrl["description"],
                    level=ctrl["level"],
                    checks=ctrl["checks"],
                    remediation=ctrl["remediation"],
                    category=cat_key,
                    category_name=cat["name"],
                    check_mode=ctrl.get("check_mode", "all"),
                )
                self._cis_controls[ctrl["id"]] = obj

        with open(nist_path, encoding="utf-8") as f:
            nist_data: dict[str, Any] = json.load(f)

        for family_key, family in nist_data["families"].items():
            for ctrl in family["controls"]:
                obj = NISTControl(
                    id=ctrl["id"],
                    title=ctrl["title"],
                    description=ctrl["description"],
                    priority=ctrl["priority"],
                    baseline=ctrl["baseline"],
                    checks=ctrl["checks"],
                    related=ctrl["related"],
                    family=family_key,
                    family_name=family["name"],
                )
                self._nist_controls[ctrl["id"]] = obj

    # ------------------------------------------------------------------
    # CIS helpers
    # ------------------------------------------------------------------

    def get_cis_control(self, control_id: str) -> CISControl | None:
        return self._cis_controls.get(control_id)

    def list_cis_controls(
        self,
        category: str | None = None,
        level: int | None = None,
    ) -> list[CISControl]:
        results = list(self._cis_controls.values())
        if category:
            results = [c for c in results if c.category == category]
        if level is not None:
            results = [c for c in results if c.level == level]
        return sorted(results, key=lambda c: c.id)

    def search_cis(self, keyword: str) -> list[CISControl]:
        kw = keyword.lower()
        return [
            c
            for c in self._cis_controls.values()
            if kw in c.title.lower() or kw in c.description.lower()
        ]

    # ------------------------------------------------------------------
    # NIST helpers
    # ------------------------------------------------------------------

    def get_nist_control(self, control_id: str) -> NISTControl | None:
        return self._nist_controls.get(control_id.upper())

    def list_nist_controls(
        self,
        family: str | None = None,
        baseline: str | None = None,
    ) -> list[NISTControl]:
        results = list(self._nist_controls.values())
        if family:
            results = [c for c in results if c.family == family.upper()]
        if baseline:
            results = [c for c in results if baseline.upper() in c.baseline]
        return sorted(results, key=lambda c: c.id)

    def search_nist(self, keyword: str) -> list[NISTControl]:
        kw = keyword.lower()
        return [
            c
            for c in self._nist_controls.values()
            if kw in c.title.lower() or kw in c.description.lower()
        ]

    # ------------------------------------------------------------------
    # Cross-reference helpers
    # ------------------------------------------------------------------

    def get_nist_families(self) -> list[tuple[str, str]]:
        """Return list of (family_code, family_name) tuples."""
        seen: dict[str, str] = {}
        for ctrl in self._nist_controls.values():
            seen[ctrl.family] = ctrl.family_name
        return sorted(seen.items())

    def get_cis_categories(self) -> list[tuple[str, str]]:
        """Return list of (category_key, category_name) tuples."""
        seen: dict[str, str] = {}
        for ctrl in self._cis_controls.values():
            seen[ctrl.category] = ctrl.category_name
        return sorted(seen.items())
