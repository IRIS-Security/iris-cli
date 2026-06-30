"""
Local policy draft cache — zero API cost for iris policy diff.

After `iris policy compile` (or `--dry-run`), the generated Cedar is cached
alongside the agent's governance files. `iris policy diff` reads that cache
offline and compares it to policy.cedar on disk.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DRAFT_FILENAME = "policy-draft.cedar"
META_FILENAME = "policy-draft.meta.json"


@dataclass
class DraftMeta:
    intent_sha256: str
    compiled_at: str
    compiler_backend: str
    compiler_model: str

    @classmethod
    def from_dict(cls, data: dict) -> "DraftMeta":
        return cls(
            intent_sha256=data["intent_sha256"],
            compiled_at=data["compiled_at"],
            compiler_backend=data.get("compiler_backend", "unknown"),
            compiler_model=data.get("compiler_model", "unknown"),
        )


@dataclass
class DraftCacheStatus:
    draft_path: Path
    meta_path: Path
    meta: Optional[DraftMeta]
    intent_sha256: str
    draft_exists: bool
    is_stale: bool


def intent_hash(intent_text: str) -> str:
    return hashlib.sha256(intent_text.encode("utf-8")).hexdigest()


def draft_paths(gov_dir: Path) -> tuple[Path, Path]:
    return gov_dir / DRAFT_FILENAME, gov_dir / META_FILENAME


def save_policy_draft(
    gov_dir: Path,
    intent_text: str,
    cedar_policy: str,
    compiler_backend: str,
    compiler_model: str,
) -> Path:
    """Write Cedar draft + metadata after compile or dry-run."""
    draft_file, meta_file = draft_paths(gov_dir)
    draft_file.write_text(cedar_policy)
    meta = DraftMeta(
        intent_sha256=intent_hash(intent_text),
        compiled_at=datetime.now(timezone.utc).isoformat(),
        compiler_backend=compiler_backend,
        compiler_model=compiler_model,
    )
    meta_file.write_text(json.dumps({
        "intent_sha256": meta.intent_sha256,
        "compiled_at": meta.compiled_at,
        "compiler_backend": meta.compiler_backend,
        "compiler_model": meta.compiler_model,
    }, indent=2))
    return draft_file


def load_draft_meta(gov_dir: Path) -> Optional[DraftMeta]:
    _, meta_file = draft_paths(gov_dir)
    if not meta_file.exists():
        return None
    try:
        return DraftMeta.from_dict(json.loads(meta_file.read_text()))
    except (json.JSONDecodeError, KeyError):
        return None


def check_draft_cache(gov_dir: Path, intent_text: str) -> DraftCacheStatus:
    draft_file, meta_file = draft_paths(gov_dir)
    current_hash = intent_hash(intent_text)
    meta = load_draft_meta(gov_dir)
    is_stale = meta is None or meta.intent_sha256 != current_hash
    return DraftCacheStatus(
        draft_path=draft_file,
        meta_path=meta_file,
        meta=meta,
        intent_sha256=current_hash,
        draft_exists=draft_file.exists(),
        is_stale=is_stale,
    )


def clear_policy_draft(gov_dir: Path) -> None:
    """Remove cached policy draft and metadata after commit."""
    draft_file, meta_file = draft_paths(gov_dir)
    if draft_file.exists():
        draft_file.unlink()
    if meta_file.exists():
        meta_file.unlink()


def load_cached_draft(gov_dir: Path, intent_text: str) -> tuple[str, DraftCacheStatus]:
    status = check_draft_cache(gov_dir, intent_text)
    if not status.draft_exists:
        raise FileNotFoundError(
            f"No cached policy draft found at {status.draft_path}\n"
            f"Run: iris policy compile --agent <name> --dry-run\n"
            f"Uses your LLM key from ANTHROPIC_API_KEY or ~/.iris/config.yaml"
        )
    return status.draft_path.read_text(), status
