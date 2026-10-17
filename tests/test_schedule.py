"""Scheduling emits defensive-only units; attack validation is never scheduled."""

from __future__ import annotations

import pytest

from sentinel.core.errors import ModeViolation
from sentinel.schedule import generate


def test_generate_systemd_and_cron():
    unit = generate("block --from-logs /var/log/auth.log", on_calendar="daily")
    assert "[Timer]" in unit.timer_text
    assert "OnCalendar=daily" in unit.timer_text
    assert "ExecStart=/usr/bin/env sentinel block --from-logs /var/log/auth.log" in unit.service_text
    assert "NoNewPrivileges=true" in unit.service_text  # unit hardening present
    assert unit.cron_line.endswith("sentinel block --from-logs /var/log/auth.log")


def test_scheduling_redteam_is_refused():
    with pytest.raises(ModeViolation):
        generate("sandbox --replica 10.0.0.5 --validate nuclei=...")
    with pytest.raises(ModeViolation):
        generate("redteam 10.0.0.5")


def test_describe_lists_all_artifacts():
    text = generate("scan 10.0.0.5", on_calendar="hourly").describe()
    assert ".service ---" in text
    assert ".timer ---" in text
    assert "cron fallback" in text
