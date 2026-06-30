"""
Parse Cedar policy strings into structured rule objects and compute diffs.

Rule identity is determined by principal + action + resource (deterministic).
Plain-English summaries use templates only — no LLM required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


COMPLIANCE_REF_PATTERN = re.compile(
    r"\b(CO-\d{3}|GDPR|HIPAA|SOC2|CCPA|PIPL|CJIS|FedRAMP)\b",
    re.IGNORECASE,
)

RULE_START_PATTERN = re.compile(r"^\s*(permit|forbid)\s*\(", re.MULTILINE | re.IGNORECASE)


@dataclass
class CedarRule:
    type: str  # "permit" | "forbid"
    principal: str
    action: str
    resource: str
    conditions: List[str] = field(default_factory=list)
    compliance_refs: List[str] = field(default_factory=list)
    plain_english: str = ""
    raw_block: str = ""

    @property
    def identity(self) -> Tuple[str, str, str]:
        return (self.principal, self.action, self.resource)

    def identity_key(self) -> str:
        return f"{self.principal}|{self.action}|{self.resource}"


@dataclass
class CedarDiff:
    status: str  # ADDED | REMOVED | MODIFIED | UNCHANGED
    old_rule: Optional[CedarRule]
    new_rule: Optional[CedarRule]
    risk_delta: str  # INCREASED | DECREASED | NEUTRAL
    risk_reason: str
    compliance_affected: List[str] = field(default_factory=list)


def parse_cedar(cedar_str: str) -> List[CedarRule]:
    """Parse a Cedar policy string into structured rule objects."""
    if not cedar_str or not cedar_str.strip():
        return []

    rules: List[CedarRule] = []
    for match in RULE_START_PATTERN.finditer(cedar_str):
        start = match.start()
        rule_type = match.group(1).lower()
        block_end = _find_block_end(cedar_str, match.end() - 1)
        block = cedar_str[start:block_end]
        comment_start = _find_comment_start(cedar_str, start)
        comment_block = cedar_str[comment_start:start]
        rules.append(_parse_rule_block(rule_type, block, comment_block))

    return rules


def diff_cedar(old: List[CedarRule], new: List[CedarRule]) -> List[CedarDiff]:
    """Diff two Cedar rule lists. Returns results sorted deterministically."""
    old_map = {r.identity_key(): r for r in old}
    new_map = {r.identity_key(): r for r in new}
    all_keys = sorted(set(old_map) | set(new_map))

    diffs: List[CedarDiff] = []
    for key in all_keys:
        old_rule = old_map.get(key)
        new_rule = new_map.get(key)

        if old_rule is None and new_rule is not None:
            status = "ADDED"
            risk_delta, risk_reason = _assess_added_risk(new_rule)
            compliance = list(new_rule.compliance_refs)
        elif new_rule is None and old_rule is not None:
            status = "REMOVED"
            risk_delta, risk_reason = _assess_removed_risk(old_rule)
            compliance = list(old_rule.compliance_refs)
        elif _rules_equal(old_rule, new_rule):
            status = "UNCHANGED"
            risk_delta, risk_reason = "NEUTRAL", "No change to this rule"
            compliance = list(dict.fromkeys(
                (old_rule.compliance_refs if old_rule else [])
                + (new_rule.compliance_refs if new_rule else [])
            ))
        else:
            status = "MODIFIED"
            risk_delta, risk_reason = _assess_modified_risk(old_rule, new_rule)
            compliance = list(dict.fromkeys(
                old_rule.compliance_refs + new_rule.compliance_refs
            ))

        diffs.append(CedarDiff(
            status=status,
            old_rule=old_rule,
            new_rule=new_rule,
            risk_delta=risk_delta,
            risk_reason=risk_reason,
            compliance_affected=compliance,
        ))

    return diffs


def _find_block_end(text: str, open_paren_idx: int) -> int:
    depth = 0
    i = open_paren_idx
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                j = i + 1
                while j < len(text) and text[j] in " \t\n\r":
                    j += 1
                if j < len(text) and text[j:].lower().startswith(("when", "unless")):
                    clause_end = _find_clause_end(text, j)
                    if text[clause_end - 1] == ";":
                        return clause_end
                    return clause_end
                if j < len(text) and text[j] == ";":
                    return j + 1
                return i + 1
        i += 1
    return len(text)


def _find_clause_end(text: str, start: int) -> int:
    brace_idx = text.find("{", start)
    if brace_idx == -1:
        return len(text)
    depth = 0
    for i in range(brace_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                j = i + 1
                while j < len(text) and text[j] in " \t\n\r":
                    j += 1
                if j < len(text) and text[j] == ";":
                    return j + 1
                return i + 1
    return len(text)


def _find_comment_start(text: str, rule_start: int) -> int:
    line_start = text.rfind("\n", 0, rule_start)
    line_start = 0 if line_start == -1 else line_start + 1

    while line_start > 0:
        prev_end = line_start - 1
        prev_start = text.rfind("\n", 0, prev_end)
        prev_start = 0 if prev_start == -1 else prev_start + 1
        prev_line = text[prev_start:prev_end + 1].strip()
        if prev_line.startswith("//") or prev_line == "":
            line_start = prev_start
        else:
            break

    return line_start


def _parse_rule_block(rule_type: str, block: str, comment_block: str) -> CedarRule:
    principal = _extract_field(block, "principal")
    action = _extract_field(block, "action")
    resource = _extract_field(block, "resource")
    conditions = _extract_conditions(block)
    compliance_refs = _extract_compliance_refs(comment_block)

    rule = CedarRule(
        type=rule_type,
        principal=principal,
        action=action,
        resource=resource,
        conditions=conditions,
        compliance_refs=compliance_refs,
        raw_block=block.strip(),
    )
    rule.plain_english = _generate_plain_english(rule)
    return rule


def _extract_field(block: str, field_name: str) -> str:
    pattern = rf"{field_name}\s*(==|in)\s*(.+?)(?:,\s*\n|\))"
    match = re.search(pattern, block, re.DOTALL | re.IGNORECASE)
    if not match:
        return ""
    op = match.group(1).strip()
    value = match.group(2).strip()
    value = re.sub(r"\s+", " ", value)
    if op == "in":
        return f"in [{value}]"
    return _normalize_cedar_value(value)


def _normalize_cedar_value(value: str) -> str:
    """Preserve iris::Type::\"name\" form for stable rule identity."""
    value = value.strip().rstrip(",")
    match = re.match(r'(iris::[\w]+::"[^"]+")', value)
    if match:
        return match.group(1)
    quoted = re.search(r'::"([^"]+)"', value)
    if quoted:
        return quoted.group(1)
    return value


def _extract_conditions(block: str) -> List[str]:
    conditions: List[str] = []
    for clause_type in ("when", "unless"):
        pattern = rf"{clause_type}\s*\{{(.*?)\}};"
        match = re.search(pattern, block, re.DOTALL | re.IGNORECASE)
        if match:
            body = match.group(1).strip()
            for part in body.split("&&"):
                part = part.strip()
                if part:
                    conditions.append(f"{clause_type}: {part}")
    return conditions


def _extract_compliance_refs(comment_block: str) -> List[str]:
    refs = COMPLIANCE_REF_PATTERN.findall(comment_block)
    normalized = []
    seen = set()
    for ref in refs:
        upper = ref.upper()
        if upper.startswith("CO-"):
            upper = upper  # keep CO-001 format
        if upper not in seen:
            seen.add(upper)
            normalized.append(upper if not upper.startswith("CO-") else ref.upper())
    return sorted(normalized, key=lambda r: (not r.startswith("CO-"), r))


def _generate_plain_english(rule: CedarRule) -> str:
    action_phrase = _action_phrase(rule.action, rule.type)
    resource_phrase = _resource_phrase(rule.resource)

    if rule.type == "permit":
        base = f"Agent may {action_phrase} {resource_phrase}".strip()
        if _has_consent_gate(rule.conditions):
            base += " with consent"
        return base

    if rule.conditions and any(c.lower().startswith("unless:") for c in rule.conditions):
        return (
            f"Agent is forbidden from {action_phrase} {resource_phrase} "
            f"unless conditions are met"
        ).strip()
    return (
        f"Agent is forbidden from {action_phrase} {resource_phrase} "
        f"when conditions are met"
    ).strip()


def _action_phrase(action: str, rule_type: str) -> str:
    if action.startswith("in ["):
        inner = action[4:-1]
        actions = re.findall(r'"([^"]+)"', inner)
        if len(actions) == 1:
            return _single_action_word(actions[0], rule_type)
        if actions:
            words = [_single_action_word(a, rule_type) for a in actions]
            return ", ".join(words[:-1]) + f" and {words[-1]}"
        return "perform actions on"

    type_match = re.match(r'iris::Action::"([^"]+)"', action)
    if type_match:
        return _single_action_word(type_match.group(1), rule_type)

    quoted = re.search(r'"([^"]+)"', action)
    if quoted:
        return _single_action_word(quoted.group(1), rule_type)
    return action or "access"


def _single_action_word(action: str, rule_type: str) -> str:
    mapping = {
        "read": "read from",
        "write": "write to",
        "call": "call",
        "execute": "execute on",
    }
    return mapping.get(action, action)


def _resource_phrase(resource: str) -> str:
    if resource.startswith("in ["):
        inner = resource[4:-1]
        names = re.findall(r'"([^"]+)"', inner)
        if not names:
            return "specified resources"
        if len(names) == 1:
            return _single_resource_phrase(names[0], inner)
        return ", ".join(_single_resource_phrase(n, inner) for n in names)

    type_match = re.match(r'iris::(\w+)::"([^"]+)"', resource)
    if type_match:
        type_name, name = type_match.group(1), type_match.group(2)
        return _single_resource_phrase(name, type_name)

    quoted = re.search(r'"([^"]+)"', resource)
    name = quoted.group(1) if quoted else resource
    return _single_resource_phrase(name, resource)


def _single_resource_phrase(name: str, raw: str) -> str:
    raw_lower = raw.lower()
    if "dataclass" in raw_lower or name.lower() == "pii":
        if name.lower() == "pii":
            return "PII data"
        return f"{name} data"
    if "api" in raw_lower or "API" in raw:
        label = name.replace("-", " ")
        if label.lower().endswith(" api"):
            return label
        return f"{label} API"
    if "Storage" in raw:
        return f"{name.replace('-', ' ')} storage"
    if "Tool" in raw:
        return f"{name.replace('-', ' ')} tool"
    return name.replace("-", " ")


def _has_consent_gate(conditions: List[str]) -> bool:
    return any("user_consent_logged" in c for c in conditions)


def _rules_equal(a: Optional[CedarRule], b: Optional[CedarRule]) -> bool:
    if a is None or b is None:
        return False
    return (
        a.type == b.type
        and a.principal == b.principal
        and a.action == b.action
        and a.resource == b.resource
        and a.conditions == b.conditions
    )


def _environment_scope(rule: CedarRule) -> str:
    for cond in rule.conditions:
        if "environment" in cond.lower():
            if "production" in cond and "dev" not in cond:
                return "production"
            if "dev" in cond and "test" in cond:
                return "all environments"
    return "unspecified scope"


def _assess_added_risk(rule: CedarRule) -> Tuple[str, str]:
    if rule.type == "permit":
        if _has_consent_gate(rule.conditions):
            return "NEUTRAL", "new capability with consent gate enforced"
        return "NEUTRAL", "new capability added, review conditions"
    return "DECREASED", "new restriction added, attack surface reduced"


def _assess_removed_risk(rule: CedarRule) -> Tuple[str, str]:
    if rule.type == "permit":
        return "INCREASED", "capability removed, agent may break at runtime"
    return "INCREASED", "restriction removed, more exposure"


def _assess_modified_risk(
    old: CedarRule,
    new: CedarRule,
) -> Tuple[str, str]:
    old_strict = _strictness_score(old)
    new_strict = _strictness_score(new)

    if new.type != old.type:
        if new.type == "forbid":
            return "DECREASED", "rule changed to forbid, scope narrowed"
        return "INCREASED", "rule changed to permit, scope widened"

    old_scope = _environment_scope(old)
    new_scope = _environment_scope(new)
    if old_scope == "all environments" and new_scope == "production":
        return "DECREASED", "narrower scope, less dev/test exposure"

    if new_strict > old_strict:
        return "DECREASED", "conditions became stricter, less exposure"
    if new_strict < old_strict:
        return "INCREASED", "conditions became looser, more exposure"
    return "NEUTRAL", "conditions changed without clear risk shift"


def _strictness_score(rule: CedarRule) -> int:
    score = 0
    if rule.type == "forbid":
        score += 10
    for cond in rule.conditions:
        lower = cond.lower()
        if "environment" in lower:
            if re.search(r'in \[[^\]]*"production"[^\]]*\]', lower):
                if "dev" in lower or "test" in lower or "staging" in lower:
                    score += 2
                else:
                    score += 8
            elif 'environment == "production"' in lower:
                score += 8
        if "user_consent_logged == true" in lower:
            score += 3
        if "user_consent_logged == false" in lower:
            score += 4
        if "unless:" in lower:
            score += 2
        if "in [" in lower:
            score += 1
    return score


def summarize_diffs(diffs: List[CedarDiff]) -> dict:
    """Return counts and compliance impact summary."""
    counts = {"ADDED": 0, "REMOVED": 0, "MODIFIED": 0, "UNCHANGED": 0}
    for d in diffs:
        counts[d.status] = counts.get(d.status, 0) + 1

    violations_opened = sum(
        1 for d in diffs
        if d.status != "UNCHANGED" and d.risk_delta == "INCREASED"
    )
    violations_closed = sum(
        1 for d in diffs
        if d.status != "UNCHANGED" and d.risk_delta == "DECREASED"
    )

    coverage: dict[str, int] = {}
    for d in diffs:
        if d.status != "UNCHANGED" and d.risk_delta == "DECREASED":
            for ref in d.compliance_affected:
                coverage[ref] = coverage.get(ref, 0) + 1

    return {
        "counts": counts,
        "violations_opened": violations_opened,
        "violations_closed": violations_closed,
        "coverage_strengthened": coverage,
    }
