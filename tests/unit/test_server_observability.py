from __future__ import annotations

from securecode_ai.server.alerts import Alerts, AlertState
from securecode_ai.server.sli import Sample, SliWindow


def test_missing_samples_are_not_success_and_alert_deduplicates() -> None:
    alerts = Alerts()
    assert alerts.evaluate(key="e", sli=SliWindow(()), metric="error_rate", threshold=0.1) is None
    window = SliWindow((Sample("error", 1, 2),))
    alert = alerts.evaluate(key="e", sli=window, metric="error_rate", threshold=0.1)
    assert alert is not None
    assert alert.state is AlertState.FIRING
    assert alerts.evaluate(key="e", sli=window, metric="error_rate", threshold=0.1) is None
