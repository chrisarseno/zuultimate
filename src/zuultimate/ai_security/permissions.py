"""RBAC permissions for C-Suite executive agents mapped to tool categories."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Set


class ToolCategory(str, Enum):
    COMMUNICATION = "communication"
    DATA = "data"
    DEVOPS = "devops"
    RESEARCH = "research"
    BUSINESS = "business"
    DOCUMENTS = "documents"
    ANALYSIS = "analysis"
    AUTOMATION = "automation"
    GENERAL = "general"
    SECURITY = "security"


ALL_CATEGORIES: FrozenSet[ToolCategory] = frozenset(ToolCategory)

# Full-access roles
_FULL = ALL_CATEGORIES

# Restricted permission sets
_BUSINESS_DATA = frozenset({
    ToolCategory.BUSINESS, ToolCategory.DATA, ToolCategory.ANALYSIS,
    ToolCategory.DOCUMENTS, ToolCategory.GENERAL,
})

_COMM_RESEARCH = frozenset({
    ToolCategory.COMMUNICATION, ToolCategory.RESEARCH,
    ToolCategory.DOCUMENTS, ToolCategory.GENERAL,
})

_DATA_RESEARCH = frozenset({
    ToolCategory.DATA, ToolCategory.RESEARCH,
    ToolCategory.ANALYSIS, ToolCategory.GENERAL,
})

_PRODUCT = frozenset({
    ToolCategory.RESEARCH, ToolCategory.ANALYSIS, ToolCategory.DOCUMENTS,
    ToolCategory.BUSINESS, ToolCategory.GENERAL,
})

_STRATEGY = frozenset({
    ToolCategory.RESEARCH, ToolCategory.ANALYSIS, ToolCategory.BUSINESS,
    ToolCategory.DOCUMENTS, ToolCategory.GENERAL,
})


@dataclass
class ExecutivePermissionRule:
    agent_code: str
    allowed_categories: FrozenSet[ToolCategory]
    description: str = ""


EXECUTIVE_TOOL_PERMISSIONS: Dict[str, ExecutivePermissionRule] = {
    "CoS": ExecutivePermissionRule("CoS", _FULL, "Chief of Staff - full access for coordination"),
    "COO": ExecutivePermissionRule("COO", _FULL, "COO/Nexus - full operations access"),
    "CTO": ExecutivePermissionRule("CTO", _FULL, "CTO - full technical access"),
    "CEngO": ExecutivePermissionRule("CEngO", _FULL, "Engineering Officer - full access"),
    "CSecO": ExecutivePermissionRule("CSecO", _FULL, "Security Officer - full access"),
    "CIO": ExecutivePermissionRule("CIO", ALL_CATEGORIES - {ToolCategory.AUTOMATION}, "Info Officer - all except automation"),
    "CFO": ExecutivePermissionRule("CFO", _BUSINESS_DATA, "CFO - business/data/analysis/docs"),
    "CMO": ExecutivePermissionRule("CMO", _COMM_RESEARCH, "CMO - communication/research/docs"),
    "CDO": ExecutivePermissionRule("CDO", _DATA_RESEARCH, "CDO - data/research/analysis"),
    "CPO": ExecutivePermissionRule("CPO", _PRODUCT, "CPO - product/research/analysis/docs"),
    "CRO": ExecutivePermissionRule("CRO", _DATA_RESEARCH | {ToolCategory.DOCUMENTS}, "Research Officer - data/research"),
    "CCO": ExecutivePermissionRule("CCO", _COMM_RESEARCH | {ToolCategory.ANALYSIS}, "Customer Officer - comm/research/analysis"),
    "CSO": ExecutivePermissionRule("CSO", _STRATEGY, "Strategy Officer - strategy/research/business"),
    "CRevO": ExecutivePermissionRule("CRevO", _BUSINESS_DATA | {ToolCategory.RESEARCH}, "Revenue Officer - business/data/research"),
    "CRiO": ExecutivePermissionRule("CRiO", _STRATEGY | {ToolCategory.SECURITY}, "Risk Officer - strategy + security"),
    "CComO": ExecutivePermissionRule("CComO", _STRATEGY | {ToolCategory.SECURITY}, "Compliance Officer - strategy + security"),
}


class ExecutivePermissions:
    """Check whether an executive agent is permitted to use a tool category."""

    def __init__(self, rules: Dict[str, ExecutivePermissionRule] | None = None):
        self._rules = rules or EXECUTIVE_TOOL_PERMISSIONS

    def check(self, agent_code: str, tool_name: str, tool_category: str) -> bool:
        rule = self._rules.get(agent_code)
        if rule is None:
            return False  # unknown agent -> deny
        try:
            cat = ToolCategory(tool_category)
        except ValueError:
            return False  # unknown category -> deny
        return cat in rule.allowed_categories

    def get_allowed_categories(self, agent_code: str) -> Set[str]:
        rule = self._rules.get(agent_code)
        if rule is None:
            return set()
        return {c.value for c in rule.allowed_categories}

    def list_agents(self) -> list[str]:
        return list(self._rules.keys())
