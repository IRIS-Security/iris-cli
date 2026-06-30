"""
Load the developer's LLM compiler settings from ~/.iris/config.yaml.

Each developer brings their own API key and chooses their provider.
Keys are never stored in the repo or shipped with the SDK.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from iris_core.engine.compiler import PolicyCompiler


DEFAULT_CONFIG_PATH = Path.home() / ".iris" / "config.yaml"

EXAMPLE_CONFIG = """\
# IRIS local configuration — stored on your machine only
# Copy to ~/.iris/config.yaml and add your API key via environment variable.

compiler:
  backend: anthropic   # anthropic | openai | google | mistral | groq | ollama | together
  model: claude-sonnet-4-6

# API keys are read from environment variables (never stored here):
#   export ANTHROPIC_API_KEY=sk-ant-...
#   export OPENAI_API_KEY=sk-...
#   export MISTRAL_API_KEY=...
#   export GROQ_API_KEY=...
# Or use LiteLLM: iris policy compile --litellm-model ollama/llama3.2
"""


def load_iris_config(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return {}
    try:
        import yaml
        data = yaml.safe_load(path.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def create_policy_compiler(
    config_path: Path | None = None,
    llm_backend: str | None = None,
    model: str | None = None,
    litellm_model: str | None = None,
) -> PolicyCompiler:
    """Build a PolicyCompiler using CLI flags and ~/.iris/config.yaml settings."""
    cfg = load_iris_config(config_path).get("compiler", {})
    return PolicyCompiler(
        llm_backend=llm_backend or cfg.get("backend"),
        model=model or cfg.get("model"),
        litellm_model=litellm_model,
    )


def compiler_info(compiler: PolicyCompiler) -> tuple[str, str]:
    if compiler._mode == "litellm":
        return "litellm", compiler._litellm_model
    if compiler._mode == "custom":
        return "custom", compiler._model
    return compiler._llm_backend, compiler._model
