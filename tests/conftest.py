import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if call.when == "call":
        report._duration = call.duration


def pytest_report_teststatus(report, config):
    if report.when == "call" and hasattr(report, "_duration"):
        d = report._duration
        time_str = f"{d*1000:.1f}ms" if d < 1 else f"{d:.2f}s"
        if report.passed:
            return "passed", "✓", f"PASSED  ({time_str})"
        elif report.failed:
            return "failed", "✗", f"FAILED  ({time_str})"