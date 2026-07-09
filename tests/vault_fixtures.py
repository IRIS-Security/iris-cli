"""Shared vault event timestamps for CLI tests (within free-tier retention window)."""

from __future__ import annotations

from datetime import datetime, timedelta


def recent_iso(*, days_ago: int = 1, hour: int = 10, minute: int = 0) -> str:
    dt = datetime.utcnow() - timedelta(days=days_ago)
    return dt.replace(hour=hour, minute=minute, second=0, microsecond=0).isoformat()


def recent_date(*, days_ago: int = 1) -> str:
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
