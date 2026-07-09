"""iris explain — transparent proxy explanation for developer trust."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

console = Console()

PLAIN_EXPLANATION = """\
IRIS wraps your LLM client. That is all.

When you call client.messages.create():
  1. IRIS checks: is this call allowed by your policy?
     Takes under 5ms. Runs in-process. No network call.
  2. If yes: the real API call proceeds unchanged.
  3. If no: IrisViolationError is raised with a plain
     English explanation of what rule was violated.
  4. Either way: the call is logged to your local
     Evidence Vault at ~/.iris/evidence/

In dev environment (IRIS_ENV=dev):
  IRIS NEVER blocks. It only warns. Your code always
  runs. You see the warning in your terminal.

Your API key stays on your machine. IRIS never sees it.
IRIS never phones home. All evaluation is local.
Your existing tests will pass without modification.

To verify: run your test suite after adding IRIS.
If any test fails, report it as a bug at:
github.com/IRIS-Security/iris-sdk/issues"""

TECHNICAL_EXPLANATION = """\
Proxy pattern (identical attribute forwarding):

  class IrisAnthropic:
      def __init__(self, passport, **kwargs):
          self._client = anthropic.Anthropic(**kwargs)  # your real client
          self._engine = CedarEngine()                   # local policy eval
          self._vault = EvidenceVault(passport.agent_id)   # local audit log

      def __getattr__(self, name):
          return getattr(self._client, name)  # every other attribute proxied

  def messages.create(self, **kwargs):
      result = evaluate_api_call(self._engine, self._passport, kwargs)
      enforce_result(result)          # DENY in prod, WARN in dev
      self._vault.record(context, result)
      return self._client.messages.create(**kwargs)  # unchanged API call

Execution flow:
  your_code → IrisAnthropic → CedarEngine (local, <5ms) → real API → your_code

Dev mode (IRIS_ENV=dev):
  enforce_result() logs violations but never raises IrisViolationError.

Test compatibility:
  IrisAnthropic.__getattr__ forwards models.list(), beta.*, etc.
  unchanged. Drop-in replacement — no test changes required."""


@click.command("explain")
@click.option("--technical", is_flag=True, help="Show code examples and execution flow")
def explain_cmd(technical: bool) -> None:
    """Explain exactly what IRIS does to your code — builds developer trust."""
    body = TECHNICAL_EXPLANATION if technical else PLAIN_EXPLANATION
    title = "What IRIS does to your code (technical)" if technical else "What IRIS does to your code"
    console.print(Panel(body, title=title, style="blue"))
