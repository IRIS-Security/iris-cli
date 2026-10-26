"""`iris hitl list` must print IDs that `iris hitl approve` accepts."""

from click.testing import CliRunner


def test_list_shows_full_id_and_approve_accepts_prefix(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from iris_cli.main import cli
    from iris_core.hitl.models import HITLReview
    from iris_core.hitl.queue import HITLQueue

    queue = HITLQueue()
    from datetime import datetime, timedelta

    review = HITLReview(review_id="rev_0123456789ab", agent_id="a1", agent_name="loan-prequal-agent",
                        tool_name="underwriting", action="decline_prequal", triggered_by_rule="step-up",
                        risk_level="HIGH", environment="production",
                        created_at=datetime.utcnow().isoformat() + "Z",
                        expires_at=(datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z")
    queue.submit(review)
    runner = CliRunner()
    listed = runner.invoke(cli, ["hitl", "list"])
    assert review.review_id in listed.output
    approved = runner.invoke(cli, ["hitl", "approve", review.review_id[:10], "--note", "ok"])
    assert approved.exit_code == 0, approved.output
    missing = runner.invoke(cli, ["hitl", "approve", "rev_nothere"])
    assert missing.exit_code != 0 and "Review not found" in missing.output
