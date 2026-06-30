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
