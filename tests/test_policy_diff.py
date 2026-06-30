"""Tests for iris policy diff and Cedar parser."""

import json

import pytest

from iris_cli.cedar_parser import CedarRule, diff_cedar, parse_cedar, summarize_diffs
from iris_cli.policy_cache import check_draft_cache, save_policy_draft
from iris_cli.policy_diff import format_diff_json, run_policy_diff


PERMIT_READ_PAYMENTS = """
// Satisfies: CO-004
permit (
  principal == iris::AgentPassport::"payment-agent",
  action    == iris::Action::"read",
  resource  == iris::API::"payments"
)
when {
  context.environment in ["dev", "test", "staging", "production"] &&
  context.user_consent_logged == true
};
"""

PERMIT_CALL_SENDGRID = """
// Satisfies: CO-004 (consent gate)
permit (
  principal == iris::AgentPassport::"payment-agent",
  action    == iris::Action::"call",
  resource  == iris::API::"sendgrid-email-api"
)
when {
  context.environment in ["dev", "test", "staging", "production"] &&
  context.user_consent_logged == true
};
"""

FORBID_PII = """
// Satisfies: CO-004, GDPR
forbid (
  principal == iris::AgentPassport::"payment-agent",
  action    == iris::Action::"write",
  resource  == iris::DataClass::"pii"
)
unless {
  context.user_consent_logged == true
};
"""

PERMIT_READ_PAYMENTS_PROD_ONLY = """
// Satisfies: CO-004
permit (
  principal == iris::AgentPassport::"payment-agent",
  action    == iris::Action::"read",
  resource  == iris::API::"payments"
)
when {
  context.environment == "production" &&
  context.user_consent_logged == true
};
"""


@pytest.fixture
def gov_dir(tmp_path):
    agent_dir = tmp_path / "governance" / "agents" / "payment-agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "passport.yaml").write_text(
        """
name: payment-agent
owner: test@example.com
team: platform
data_classification: pii
compliance_tags:
  - colorado-ai-act
environments:
  - dev
is_high_risk_ai: true
"""
    )
    (agent_dir / "policy-intent.md").write_text("# Intent\nAllow payments access.")
    return agent_dir


@pytest.fixture
def sample_old_cedar():
    return PERMIT_READ_PAYMENTS + FORBID_PII


@pytest.fixture
def sample_new_cedar():
    return PERMIT_READ_PAYMENTS + PERMIT_CALL_SENDGRID + FORBID_PII


def test_diff_detects_added_rule(sample_old_cedar, sample_new_cedar):
    old_rules = parse_cedar(sample_old_cedar)
    new_rules = parse_cedar(sample_new_cedar)
    diffs = diff_cedar(old_rules, new_rules)

    added = [d for d in diffs if d.status == "ADDED"]
    assert len(added) == 1
    assert added[0].new_rule.action == 'iris::Action::"call"'
    assert "sendgrid" in added[0].new_rule.resource.lower()
    assert added[0].risk_delta == "NEUTRAL"
    assert "CO-004" in added[0].compliance_affected


def test_diff_detects_removed_permit_as_increased_risk():
    old = parse_cedar(PERMIT_READ_PAYMENTS + PERMIT_CALL_SENDGRID)
    new = parse_cedar(PERMIT_READ_PAYMENTS)
    diffs = diff_cedar(old, new)

    removed = [d for d in diffs if d.status == "REMOVED"]
    assert len(removed) == 1
    assert removed[0].old_rule.type == "permit"
    assert removed[0].risk_delta == "INCREASED"
    assert "capability removed" in removed[0].risk_reason.lower()


def test_diff_detects_added_forbid_as_decreased_risk(sample_old_cedar):
    old = parse_cedar(PERMIT_READ_PAYMENTS)
    new = parse_cedar(PERMIT_READ_PAYMENTS + FORBID_PII)
    diffs = diff_cedar(old, new)

    added = [d for d in diffs if d.status == "ADDED"]
    assert len(added) == 1
    assert added[0].new_rule.type == "forbid"
    assert added[0].risk_delta == "DECREASED"
    assert "restriction" in added[0].risk_reason.lower()


def test_diff_unchanged_not_shown_by_default(sample_old_cedar, sample_new_cedar):
    old_rules = parse_cedar(sample_old_cedar)
    new_rules = parse_cedar(sample_new_cedar)
    all_diffs = diff_cedar(old_rules, new_rules)
    visible = [d for d in all_diffs if d.status != "UNCHANGED"]

    unchanged = [d for d in all_diffs if d.status == "UNCHANGED"]
    assert len(unchanged) >= 1
    assert all(d.status != "UNCHANGED" for d in visible)


def test_diff_compliance_impact_shown():
    old = parse_cedar(PERMIT_READ_PAYMENTS)
    new = parse_cedar(PERMIT_READ_PAYMENTS_PROD_ONLY)
    diffs = diff_cedar(old, new)
    summary = summarize_diffs(diffs)

    modified = [d for d in diffs if d.status == "MODIFIED"]
    assert len(modified) == 1
    assert "CO-004" in modified[0].compliance_affected
    assert modified[0].risk_delta == "DECREASED"
    assert summary["violations_opened"] == 0
    assert summary["coverage_strengthened"].get("CO-004", 0) >= 1


def test_diff_json_output(sample_old_cedar, sample_new_cedar, gov_dir):
    (gov_dir / "policy.cedar").write_text(sample_old_cedar)
    intent = (gov_dir / "policy-intent.md").read_text()
    save_policy_draft(gov_dir, intent, sample_new_cedar, "anthropic", "claude-sonnet-4-6")

    result = run_policy_diff(
        agent="payment-agent",
        governance_dir=gov_dir,
    )
    payload = json.loads(format_diff_json(result))

    assert payload["agent"] == "payment-agent"
    assert payload["draft_stale"] is False
    assert "summary" in payload
    assert payload["summary"]["counts"]["ADDED"] == 1
    assert len(payload["diffs"]) == 1
    assert payload["diffs"][0]["status"] == "ADDED"
    assert payload["diffs"][0]["risk_delta"] == "NEUTRAL"


def test_diff_uses_cached_draft_offline(sample_old_cedar, sample_new_cedar, gov_dir):
    (gov_dir / "policy.cedar").write_text(sample_old_cedar)
    intent = (gov_dir / "policy-intent.md").read_text()
    save_policy_draft(gov_dir, intent, sample_new_cedar, "openai", "gpt-4o")

    result = run_policy_diff(agent="payment-agent", governance_dir=gov_dir)
    assert result.summary["counts"]["ADDED"] == 1
    assert result.draft_stale is False
    assert result.draft_status.meta.compiler_backend == "openai"


def test_diff_detects_stale_draft(sample_old_cedar, sample_new_cedar, gov_dir):
    (gov_dir / "policy.cedar").write_text(sample_old_cedar)
    save_policy_draft(
        gov_dir,
        "old intent text",
        sample_new_cedar,
        "anthropic",
        "claude-sonnet-4-6",
    )

    result = run_policy_diff(agent="payment-agent", governance_dir=gov_dir)
    assert result.draft_stale is True


def test_diff_missing_draft_raises_helpful_error(gov_dir):
    (gov_dir / "policy.cedar").write_text(PERMIT_READ_PAYMENTS)

    with pytest.raises(FileNotFoundError, match="No cached policy draft"):
        run_policy_diff(agent="payment-agent", governance_dir=gov_dir)


def test_save_and_check_draft_cache(gov_dir):
    intent = "# Intent\nAllow payments."
    save_policy_draft(gov_dir, intent, PERMIT_READ_PAYMENTS, "anthropic", "test-model")
    status = check_draft_cache(gov_dir, intent)
    assert status.draft_exists
    assert status.is_stale is False

    status_after_edit = check_draft_cache(gov_dir, intent + "\nMore text.")
    assert status_after_edit.is_stale is True


def test_cedar_parser_extracts_permit():
    rules = parse_cedar(PERMIT_READ_PAYMENTS)
    assert len(rules) == 1
    assert rules[0].type == "permit"
    assert "read" in rules[0].plain_english.lower()
    assert "payments" in rules[0].plain_english.lower()
    assert rules[0].compliance_refs == ["CO-004"]


def test_cedar_parser_extracts_forbid_with_unless():
    rules = parse_cedar(FORBID_PII)
    assert len(rules) == 1
    assert "forbidden" in rules[0].plain_english.lower()
    assert "PII" in rules[0].plain_english
    assert "CO-004" in rules[0].compliance_refs
    assert "GDPR" in rules[0].compliance_refs


def test_plain_english_generation():
    permit = parse_cedar(PERMIT_READ_PAYMENTS)[0]
    assert permit.plain_english == "Agent may read from payments API with consent"

    forbid = parse_cedar(FORBID_PII)[0]
    assert forbid.plain_english == (
        "Agent is forbidden from write to PII data unless conditions are met"
    )

    sendgrid = parse_cedar(PERMIT_CALL_SENDGRID)[0]
    assert "call" in sendgrid.plain_english.lower()
    assert "sendgrid" in sendgrid.plain_english.lower()
    assert "consent" in sendgrid.plain_english.lower()
