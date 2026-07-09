# Copyright 2024-2025 Gilbert Martin / IRIS Security, Inc.
# All Rights Reserved. Proprietary and Confidential.

"""Tests for GitHub Pages docs sync checker."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_check_docs_pages_passes():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "check_docs_pages.py")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_workflow_requirements_cover_new_cli_commands():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_docs_pages",
        REPO_ROOT / "scripts" / "check_docs_pages.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    required = {
        "iris list",
        "iris policy status",
        "iris policy commit",
        "iris evidence query",
    }
    mentioned = set()
    for mentions in module.WORKFLOW_DOC_REQUIREMENTS.values():
        mentioned.update(mentions)
    assert required.issubset(mentioned)


def _load_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_docs_pages",
        REPO_ROOT / "scripts" / "check_docs_pages.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_sitemap_staleness_check_skips_on_shallow_clone(monkeypatch):
    """A shallow clone (actions/checkout's default fetch-depth: 1) only has
    the tip commit -- `git log` for any existing path just returns that one
    commit's date, which is as unreliable as the filesystem-mtime bug this
    replaced. The check must skip rather than false-alarm on every page."""
    module = _load_module()
    monkeypatch.setattr(module, "_is_shallow_repo", lambda: True)
    monkeypatch.setattr(
        module, "_git_last_commit_date", lambda path: "2099-01-01"
    )  # would flag every page as stale if the shallow guard didn't skip first
    errors: list[str] = []
    module._check_sitemap_dates(errors)
    assert errors == []


def test_sitemap_staleness_check_flags_real_drift_on_full_clone(monkeypatch):
    """With full history available, a page genuinely newer than its sitemap
    entry must still be caught."""
    module = _load_module()
    monkeypatch.setattr(module, "_is_shallow_repo", lambda: False)
    monkeypatch.setattr(module, "_git_last_commit_date", lambda path: "2099-01-01")
    errors: list[str] = []
    module._check_sitemap_dates(errors)
    assert errors and "stale" in errors[0].lower()


def test_sitemap_staleness_check_does_not_use_filesystem_mtime():
    """actions/checkout resets every file's mtime to checkout time, so
    reading mtime always looks like "today" regardless of real history --
    that was the original bug. Guard against reintroducing it."""
    source = (REPO_ROOT / "scripts" / "check_docs_pages.py").read_text()
    assert "st_mtime" not in source
