#!/usr/bin/env python3
"""Tests for cronstampede.py (stdlib unittest)."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cronstampede  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "cronstampede.py")
START = "2026-11-09T00:00:00"  # a Monday, in UTC unless stated


def audit(text, **kw):
    kw.setdefault("tz_override", "UTC")
    start = cronstampede.parse_from(START, ZoneInfo("UTC"))
    return cronstampede.audit_text(text, start=start, **kw)


def codes(report, severity=None):
    return [f["code"] for f in report["findings"]
            if severity is None or f["severity"] == severity]


def run_cli(*argv):
    return subprocess.run([sys.executable, TOOL, *argv],
                          capture_output=True, text=True)


class TestAuditBasics(unittest.TestCase):
    def test_simple_daily_job(self):
        report = audit("0 9 * * * /bin/true\n")
        self.assertEqual(report["summary"],
                         {"jobs": 1, "errors": 0, "warnings": 0})
        job = report["jobs"][0]
        self.assertEqual(job["next_runs"][0], "2026-11-09T09:00:00+00:00")
        self.assertIn("at 09:00", job["explain"])

    def test_weekday_range_skips_weekend(self):
        # From Monday 2026-11-09: runs Mon-Fri, then Monday again.
        report = audit("30 8 * * 1-5 /bin/true\n", next_count=6)
        runs = report["jobs"][0]["next_runs"]
        self.assertEqual(len(runs), 6)
        self.assertTrue(runs[4].startswith("2026-11-13T08:30"))  # Friday
        self.assertTrue(runs[5].startswith("2026-11-16T08:30"))  # Monday

    def test_macro_daily_and_hourly(self):
        report = audit("@daily /bin/a\n@hourly /bin/b\n")
        self.assertEqual(report["summary"]["jobs"], 2)
        self.assertEqual(report["jobs"][0]["next_runs"][0],
                         "2026-11-10T00:00:00+00:00")
        self.assertEqual(report["jobs"][1]["next_runs"][0],
                         "2026-11-09T01:00:00+00:00")

    def test_reboot_job_is_info_only(self):
        report = audit("@reboot /bin/boot\n")
        self.assertIn("reboot-job", codes(report))
        self.assertEqual(report["summary"]["errors"], 0)
        self.assertEqual(report["jobs"][0]["next_runs"], [])

    def test_names_and_sunday_seven(self):
        report = audit("0 10 * JAN SUN /bin/a\n0 10 * * 7 /bin/b\n")
        # Both describe Sunday in January (via name and via 7).
        a = report["jobs"][0]["next_runs"][0]
        self.assertTrue(a.startswith("2027-01-03T10:00"))  # a Sunday
        b_runs = report["jobs"][1]["next_runs"][0]
        self.assertTrue(b_runs.startswith("2026-11-15T"))  # next Sunday

    def test_system_mode_user_field(self):
        report = audit("15 2 * * * root /bin/nightly\n", system=True)
        self.assertEqual(report["jobs"][0]["user"], "root")
        self.assertEqual(report["jobs"][0]["command"], "/bin/nightly")

    def test_env_lines_and_comments_ignored(self):
        text = "# comment\nSHELL=/bin/bash\nMAILTO=ops@example.com\n\n0 5 * * * /bin/x\n"
        report = audit(text)
        self.assertEqual(report["summary"]["jobs"], 1)
        self.assertEqual(report["summary"]["errors"], 0)


class TestFindings(unittest.TestCase):
    def test_invalid_field_is_error(self):
        report = audit("99 9 * * * /bin/x\n")
        self.assertIn("invalid-field", codes(report, "error"))
        self.assertEqual(report["summary"]["jobs"], 0)

    def test_invalid_line_too_few_fields(self):
        report = audit("0 9 * *\n")
        self.assertIn("invalid-line", codes(report, "error"))

    def test_unknown_macro(self):
        report = audit("@fortnightly /bin/x\n")
        self.assertIn("invalid-line", codes(report, "error"))

    def test_impossible_date_never_runs(self):
        report = audit("0 0 31 2 * /bin/x\n")  # February 31st
        self.assertIn("never-runs", codes(report, "error"))
        self.assertEqual(report["jobs"][0]["next_runs"], [])

    def test_feb29_runs_on_leap_year(self):
        report = audit("0 12 29 2 * /bin/x\n")
        self.assertNotIn("never-runs", codes(report))
        self.assertTrue(
            report["jobs"][0]["next_runs"][0].startswith("2028-02-29"))

    def test_dom_dow_or_rule_and_warning(self):
        # 1st of month OR Monday: from Mon Nov 9 00:00 the job fires
        # that same Monday (OR), then Mon Nov 16 — under AND semantics
        # the first run would wait for a Monday that is also the 1st.
        report = audit("0 9 1 * 1 /bin/x\n")
        self.assertIn("dom-dow-or", codes(report, "warning"))
        self.assertTrue(
            report["jobs"][0]["next_runs"][0].startswith("2026-11-09"))
        self.assertTrue(
            report["jobs"][0]["next_runs"][1].startswith("2026-11-16"))

    def test_unescaped_percent_but_not_escaped(self):
        report = audit("0 9 * * * /bin/date +%Y\n0 9 * * * /bin/date +\\%Y\n")
        pct = [f for f in report["findings"]
               if f["code"] == "unescaped-percent"]
        self.assertEqual(len(pct), 1)
        self.assertEqual(pct[0]["line"], 1)

    def test_duplicate_job(self):
        report = audit("0 9 * * * /bin/x\n0 9 * * * /bin/x\n")
        self.assertIn("duplicate-job", codes(report, "warning"))

    def test_too_frequent(self):
        report = audit("*/2 * * * * /bin/x\n")
        self.assertIn("too-frequent", codes(report, "warning"))

    def test_missing_final_newline(self):
        report = audit("0 9 * * * /bin/x")  # no trailing newline
        self.assertIn("missing-final-newline", codes(report, "warning"))

    def test_herd_detected_at_threshold(self):
        text = "".join(f"15 6 * * * /bin/job{i}\n" for i in range(3))
        report = audit(text)
        herds = [f for f in report["findings"] if f["code"] == "herd"]
        self.assertEqual(len(herds), 1)
        self.assertIn("3 jobs", herds[0]["message"])

    def test_herd_below_threshold_quiet(self):
        text = "".join(f"15 6 * * * /bin/job{i}\n" for i in range(2))
        report = audit(text)
        self.assertNotIn("herd", codes(report))

    def test_cron_tz_switches_following_jobs(self):
        text = ("CRON_TZ=America/New_York\n"
                "0 9 * * * /bin/x\n")
        start = cronstampede.parse_from(START, ZoneInfo("UTC"))
        report = cronstampede.audit_text(text, start=start)
        job = report["jobs"][0]
        self.assertEqual(job["timezone"], "America/New_York")
        # 09:00 New York = 14:00 UTC in November (EST).
        self.assertTrue(job["next_runs"][0].startswith("2026-11-09T09:00"))
        self.assertIn("-05:00", job["next_runs"][0])

    def test_invalid_cron_tz_warns_and_keeps_previous(self):
        text = "CRON_TZ=Not/AZone\n0 9 * * * /bin/x\n"
        report = audit(text)
        self.assertIn("invalid-tz", codes(report, "warning"))
        self.assertEqual(report["jobs"][0]["timezone"], "UTC")

    def test_dst_spring_forward_gap_is_skipped(self):
        # America/New_York springs forward 2027-03-14: 02:30 never occurs.
        text = "30 2 * * * /bin/x\n"
        start = cronstampede.parse_from("2027-03-13T00:00:00",
                                    ZoneInfo("America/New_York"))
        report = cronstampede.audit_text(
            text, tz_override="America/New_York", start=start)
        runs = report["jobs"][0]["next_runs"]
        self.assertTrue(runs[0].startswith("2027-03-13T02:30"))
        self.assertTrue(runs[1].startswith("2027-03-15T02:30"))


class TestCliContract(unittest.TestCase):
    def _write(self, text):
        fh = tempfile.NamedTemporaryFile(
            "w", suffix=".crontab", delete=False)
        fh.write(text)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_cli_clean_exit_0(self):
        path = self._write("0 9 * * * /bin/true\n")
        proc = run_cli("audit", path, "--from", START, "--tz", "UTC")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("cronstampede: 1 jobs, 0 errors", proc.stdout)

    def test_cli_error_exit_1(self):
        path = self._write("0 0 31 2 * /bin/x\n")
        proc = run_cli("audit", path, "--from", START, "--tz", "UTC")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("never-runs", proc.stdout)

    def test_cli_missing_file_exit_2(self):
        proc = run_cli("audit", "/nonexistent/nope.crontab")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cronstampede:", proc.stderr)

    def test_cli_json_deterministic(self):
        path = self._write("@daily /bin/a\n0 9 1 * 1 /bin/b\n")
        argv = ("audit", path, "--from", START, "--tz", "UTC", "--json")
        first = run_cli(*argv)
        second = run_cli(*argv)
        self.assertEqual(first.stdout, second.stdout)
        parsed = json.loads(first.stdout)
        self.assertEqual(parsed["tool"], "cronstampede")

    def test_explain_weekday_job(self):
        proc = run_cli("explain", "0 9 * * 1-5", "--from", START,
                       "--tz", "UTC")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("09:00", proc.stdout)
        self.assertIn("2026-11-09T09:00:00+00:00", proc.stdout)

    def test_explain_invalid_exit_2(self):
        proc = run_cli("explain", "61 9 * * *")
        self.assertEqual(proc.returncode, 2)

    def test_explain_never_exit_1(self):
        proc = run_cli("explain", "0 0 31 2 *", "--from", START)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("never", proc.stdout)

    def test_version(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)

    def test_main_json_shape(self):
        buf = io.StringIO()
        path = self._write("0 9 * * * /bin/true\n")
        with redirect_stdout(buf):
            rc = cronstampede.main(["audit", path, "--from", START,
                                "--tz", "UTC", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["summary"]["jobs"], 1)
        self.assertEqual(data["jobs"][0]["command"], "/bin/true")


if __name__ == "__main__":
    unittest.main()
