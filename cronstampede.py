#!/usr/bin/env python3
"""CronStampede - audit a whole crontab file, not just one expression.

Validates every job in a crontab, explains each schedule in plain
English, computes DST-correct next runs in the file's own timezone,
and reports whole-file findings: pile-ups (herds), impossible dates,
never-running jobs, day-of-month/day-of-week OR-rule surprises,
too-frequent jobs, duplicates, and unescaped % in commands.

Single file, Python standard library only, no network, read-only.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

VERSION = "1.0.0"
TOOL = "cronstampede"

MONTH_NAMES = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
    "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}
MONTH_LABELS = ["", "January", "February", "March", "April", "May",
                "June", "July", "August", "September", "October",
                "November", "December"]
DOW_NAMES = {
    "SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
}
DOW_LABELS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday",
              "Friday", "Saturday"]

MACROS = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}

FIELDS = [
    ("minute", 0, 59, None),
    ("hour", 0, 23, None),
    ("day-of-month", 1, 31, None),
    ("month", 1, 12, MONTH_NAMES),
    ("day-of-week", 0, 7, DOW_NAMES),
]

ENV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
HORIZON_DAYS = 1462
HERD_WINDOW_DAYS = 7


class FieldError(ValueError):
    pass


def _atom_value(token, names, lo, hi, field_name):
    tok = token.strip().upper()
    if names and tok in names:
        return names[tok]
    if not re.fullmatch(r"\d+", tok):
        raise FieldError(f"{field_name}: bad value {token!r}")
    value = int(tok)
    if value < lo or value > hi:
        raise FieldError(
            f"{field_name}: value {value} out of range {lo}-{hi}")
    return value


def parse_field(text, field_name, lo, hi, names):
    """Parse one cron field into a set of ints (dow 7 normalized to 0)."""
    values = set()
    text = text.strip()
    if not text:
        raise FieldError(f"{field_name}: empty field")
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise FieldError(f"{field_name}: empty list element")
        step = 1
        base = part
        if "/" in part:
            base, _, step_text = part.partition("/")
            if not re.fullmatch(r"\d+", step_text) or int(step_text) < 1:
                raise FieldError(f"{field_name}: bad step in {part!r}")
            step = int(step_text)
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, _, b = base.partition("-")
            start = _atom_value(a, names, lo, hi, field_name)
            end = _atom_value(b, names, lo, hi, field_name)
            if end < start:
                raise FieldError(f"{field_name}: reversed range {base!r}")
        elif "/" in part:
            start = _atom_value(base, names, lo, hi, field_name)
            end = hi
        else:
            start = end = _atom_value(base, names, lo, hi, field_name)
        for v in range(start, end + 1, step):
            values.add(v)
    if field_name == "day-of-week":
        values = {0 if v == 7 else v for v in values}
    if not values:
        raise FieldError(f"{field_name}: no values")
    return values


class Schedule:
    def __init__(self, fields_text):
        if len(fields_text) != 5:
            raise FieldError(
                f"schedule: expected 5 fields, got {len(fields_text)}")
        parsed = []
        for text, (name, lo, hi, names) in zip(fields_text, FIELDS):
            parsed.append(parse_field(text, name, lo, hi, names))
        (self.minutes, self.hours, self.dom, self.months,
         self.dow) = parsed
        self.fields_text = list(fields_text)
        self.dom_restricted = self.dom != set(range(1, 32))
        self.dow_restricted = self.dow != set(range(0, 7))

    def key(self):
        return (tuple(sorted(self.minutes)), tuple(sorted(self.hours)),
                tuple(sorted(self.dom)), tuple(sorted(self.months)),
                tuple(sorted(self.dow)))

    def day_matches(self, date):
        if date.month not in self.months:
            return False
        dom_match = date.day in self.dom
        cron_dow = (date.weekday() + 1) % 7
        dow_match = cron_dow in self.dow
        if self.dom_restricted and self.dow_restricted:
            return dom_match or dow_match
        if self.dom_restricted:
            return dom_match
        if self.dow_restricted:
            return dow_match
        return True


def _wall_exists(dt):
    """True if an aware local wall time really occurs (not a DST gap)."""
    round_trip = dt.astimezone(timezone.utc).astimezone(dt.tzinfo)
    return (round_trip.replace(tzinfo=None) == dt.replace(tzinfo=None)
            and round_trip.utcoffset() == dt.utcoffset())


def next_runs(schedule, start, count, horizon_days=HORIZON_DAYS):
    """Next `count` run instants strictly after `start` (aware)."""
    tz = start.tzinfo
    runs = []
    day = start.date()
    hours = sorted(schedule.hours)
    minutes = sorted(schedule.minutes)
    for offset in range(horizon_days + 1):
        date = day + timedelta(days=offset)
        if schedule.day_matches(date):
            for h in hours:
                for m in minutes:
                    candidate = datetime(date.year, date.month, date.day,
                                         h, m, tzinfo=tz)
                    if candidate <= start:
                        continue
                    if not _wall_exists(candidate):
                        continue
                    runs.append(candidate)
                    if len(runs) >= count:
                        return runs
    return runs


def _num_list(values):
    vals = sorted(values)
    if len(vals) == 1:
        return str(vals[0])
    return ", ".join(str(v) for v in vals)


def explain(schedule):
    """Deterministic plain-English description of a schedule."""
    ft = schedule.fields_text
    single_min = len(schedule.minutes) == 1
    single_hour = len(schedule.hours) == 1
    if single_min and single_hour:
        time_part = (f"at {next(iter(schedule.hours)):02d}:"
                     f"{next(iter(schedule.minutes)):02d}")
    elif ft[0] == "*" and single_hour:
        time_part = f"every minute of hour {next(iter(schedule.hours)):02d}"
    elif ft[0] == "*" and ft[1] == "*":
        time_part = "every minute"
    elif single_hour and ft[0].startswith("*/"):
        time_part = (f"every {ft[0][2:]} minutes of hour "
                     f"{next(iter(schedule.hours)):02d}")
    elif ft[1] == "*":
        time_part = f"at minute {_num_list(schedule.minutes)} of every hour"
    else:
        time_part = (f"at minute {_num_list(schedule.minutes)}, "
                     f"hour {_num_list(schedule.hours)}")
    parts = [time_part]
    if schedule.dom_restricted and schedule.dow_restricted:
        dom_part = "day-of-month " + _num_list(schedule.dom)
        dow_part = (" or ".join(DOW_LABELS[d] for d in sorted(schedule.dow))
                    if len(schedule.dow) <= 3 else
                    "day-of-week " + _num_list(schedule.dow))
        parts.append(f"on {dom_part} or on {dow_part} "
                     f"(either day field may match)")
    elif schedule.dom_restricted:
        parts.append("on day-of-month " + _num_list(schedule.dom))
    elif schedule.dow_restricted:
        if len(schedule.dow) <= 3:
            names = ", ".join(DOW_LABELS[d] for d in sorted(schedule.dow))
            parts.append(f"on {names}")
        else:
            parts.append("on day-of-week " + _num_list(schedule.dow))
    if schedule.months != set(range(1, 13)):
        if len(schedule.months) <= 3:
            names = ", ".join(MONTH_LABELS[m] for m in sorted(schedule.months))
            parts.append(f"in {names}")
        else:
            parts.append("in month " + _num_list(schedule.months))
    return "; ".join(parts)


def _finding(severity, code, line, message, time_iso=None):
    f = {"severity": severity, "code": code, "line": line,
         "message": message}
    if time_iso is not None:
        f["time"] = time_iso
    return f


def parse_from(text, tz):
    """Parse --from: ISO text; naive values are read in `tz`."""
    raw = text.strip()
    try:
        if raw.endswith("Z"):
            dt = datetime.fromisoformat(raw[:-1] + "+00:00")
        else:
            dt = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError(f"bad --from value: {text!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt


def load_tz(name):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        raise ValueError(f"unknown timezone: {name!r}")


def audit_text(text, tz_override=None, system=False, start=None,
               next_count=3, herd_threshold=3, default_tz_name="UTC"):
    findings = []
    jobs = []
    if text and not text.endswith("\n"):
        findings.append(_finding(
            "warning", "missing-final-newline", 0,
            "file does not end with a newline; some cron daemons "
            "ignore the last line"))
    current_tz_name = tz_override or default_tz_name
    try:
        current_tz = load_tz(current_tz_name)
    except ValueError as exc:
        raise ValueError(str(exc))
    base_start = start
    seen = {}
    herd_hits = {}  # iso minute -> set of job line numbers
    lines = text.splitlines()
    job_index = 0
    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        env_match = ENV_RE.match(line)
        if env_match and not line.startswith("@"):
            name, value = env_match.group(1), env_match.group(2).strip()
            if name in ("CRON_TZ", "TZ"):
                tz_value = value.strip("'\"").split()[0] if value.strip() \
                    else ""
                if tz_value:
                    try:
                        loaded = load_tz(tz_value)
                    except ValueError:
                        findings.append(_finding(
                            "warning", "invalid-tz", lineno,
                            f"{name}={tz_value!r} is not a known IANA "
                            f"timezone; keeping {current_tz_name}"))
                    else:
                        if tz_override is None:
                            current_tz_name = tz_value
                            current_tz = loaded
            continue
        # Job line.
        job_index += 1
        job_start = base_start
        if job_start is None:
            job_start = datetime.now(current_tz)
        else:
            job_start = job_start.astimezone(current_tz)
        is_reboot = False
        user = None
        schedule_text = None
        if line.startswith("@"):
            parts = line.split(None, 1)
            macro = parts[0].lower()
            rest = parts[1] if len(parts) > 1 else ""
            if macro == "@reboot":
                is_reboot = True
                command = rest
                if system:
                    uparts = command.split(None, 1)
                    if len(uparts) == 2:
                        user, command = uparts
                    elif len(uparts) == 1:
                        user, command = uparts[0], ""
                jobs.append({
                    "line": lineno, "schedule": "@reboot",
                    "command": command, "user": user,
                    "timezone": current_tz_name, "reboot": True,
                    "explain": "once at startup (@reboot)",
                    "next_runs": [],
                })
                findings.append(_finding(
                    "info", "reboot-job", lineno,
                    "@reboot job: runs once at daemon startup, "
                    "not on a schedule"))
                continue
            if macro not in MACROS:
                findings.append(_finding(
                    "error", "invalid-line", lineno,
                    f"unknown macro {macro!r}"))
                continue
            schedule_text = MACROS[macro]
            fields = schedule_text.split()
            command = rest
            sched_display = macro
        else:
            tokens = line.split(None, 6 if system else 5)
            if len(tokens) < (7 if system else 6):
                findings.append(_finding(
                    "error", "invalid-line", lineno,
                    "line has too few fields for a cron job"))
                continue
            fields = tokens[:5]
            if system:
                user = tokens[5]
                command = tokens[6]
            else:
                command = tokens[5]
            sched_display = " ".join(fields)
        try:
            schedule = Schedule(fields)
        except FieldError as exc:
            findings.append(_finding(
                "error", "invalid-field", lineno, str(exc)))
            continue
        # Percent trap: an unescaped % in the command becomes a newline.
        if re.search(r"(?<!\\)%", command):
            findings.append(_finding(
                "warning", "unescaped-percent", lineno,
                "command contains an unescaped %; cron replaces it "
                "with a newline (escape it as \\%)"))
        if schedule.dom_restricted and schedule.dow_restricted:
            findings.append(_finding(
                "warning", "dom-dow-or", lineno,
                "both day-of-month and day-of-week are restricted; "
                "cron runs when EITHER matches, not both"))
        dup_key = (schedule.key(), command.strip(),
                   user, current_tz_name)
        if dup_key in seen:
            findings.append(_finding(
                "warning", "duplicate-job", lineno,
                f"same schedule and command as line {seen[dup_key]}"))
        else:
            seen[dup_key] = lineno
        runs_needed = max(next_count, 3)
        runs = next_runs(schedule, job_start, runs_needed)
        if not runs:
            findings.append(_finding(
                "error", "never-runs", lineno,
                "schedule has no run in the next "
                f"{HORIZON_DAYS} days (impossible or expired date)"))
        else:
            for a, b in zip(runs, runs[1:]):
                if (b - a) < timedelta(minutes=5):
                    findings.append(_finding(
                        "warning", "too-frequent", lineno,
                        "job can run more often than every 5 minutes"))
                    break
            # Herd accounting: runs inside the herd window.
            window_end = job_start + timedelta(days=HERD_WINDOW_DAYS)
            window_runs = next_runs(schedule, job_start, 10000,
                                    horizon_days=HERD_WINDOW_DAYS)
            for run in window_runs:
                if run > window_end:
                    break
                herd_hits.setdefault(run.isoformat(), set()).add(lineno)
        jobs.append({
            "line": lineno, "schedule": sched_display,
            "command": command, "user": user,
            "timezone": current_tz_name, "reboot": False,
            "explain": explain(schedule),
            "next_runs": [r.isoformat() for r in runs[:next_count]],
        })
    herd_seen = set()
    for iso in sorted(herd_hits):
        members = sorted(herd_hits[iso])
        if len(members) < herd_threshold:
            continue
        # One finding per (member set, wall-clock minute): a daily
        # pile-up is one herd, reported at its earliest occurrence.
        dedup_key = (tuple(members), iso[11:16])
        if dedup_key in herd_seen:
            continue
        herd_seen.add(dedup_key)
        findings.append(_finding(
            "warning", "herd", 0,
            f"{len(members)} jobs fire at the same minute "
            f"(lines {', '.join(str(m) for m in members)})",
            time_iso=iso))
    findings.sort(key=lambda f: (f["line"], f["code"],
                                 f.get("time", ""), f["message"]))
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    return {
        "tool": TOOL, "version": VERSION,
        "jobs": jobs, "findings": findings,
        "summary": {"jobs": len(jobs), "errors": errors,
                    "warnings": warnings},
    }


def render_text(report):
    out = []
    for job in report["jobs"]:
        out.append(f"line {job['line']}: {job['schedule']} "
                   f"{job['command']}")
        out.append(f"  {job['explain']} [{job['timezone']}]")
        if job["reboot"]:
            out.append("  next: at startup")
        elif job["next_runs"]:
            out.append("  next: " + ", ".join(job["next_runs"]))
        else:
            out.append("  next: never (within 4 years)")
    for f in report["findings"]:
        where = f"line {f['line']}" if f["line"] else "file"
        when = f" at {f['time']}" if "time" in f else ""
        out.append(f"finding: [{f['severity']}] {f['code']} "
                   f"{where}{when}: {f['message']}")
    s = report["summary"]
    out.append(f"cronstampede: {s['jobs']} jobs, {s['errors']} errors, "
               f"{s['warnings']} warnings")
    return "\n".join(out) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cronstampede",
        description="Audit a whole crontab file: validation, plain-"
                    "English schedules, DST-correct next runs, and "
                    "whole-file findings (herds, impossible dates, "
                    "silent traps).")
    parser.add_argument("--version", action="version",
                        version=f"cronstampede {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--tz", default=None,
                        help="IANA timezone override")
    common.add_argument("--from", dest="from_text", default=None,
                        help="start instant, ISO 8601")
    common.add_argument("--next", type=int, default=3,
                        help="number of next runs to show (default 3)")
    common.add_argument("--json", action="store_true",
                        help="emit the report as JSON")
    p_audit = sub.add_parser("audit", parents=[common],
                             help="audit a crontab file")
    p_audit.add_argument("file")
    p_audit.add_argument("--system", action="store_true",
                         help="system crontab (user field present)")
    p_audit.add_argument("--herd-threshold", type=int, default=3)
    p_explain = sub.add_parser("explain", parents=[common],
                               help="explain one cron expression")
    p_explain.add_argument("expr")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    tz_override = None
    tz = None
    if args.tz:
        try:
            tz = load_tz(args.tz)
        except ValueError as exc:
            print(f"cronstampede: {exc}", file=sys.stderr)
            return 2
        tz_override = args.tz
    start = None
    if getattr(args, "from_text", None):
        try:
            start = parse_from(args.from_text, tz or ZoneInfo("UTC"))
        except ValueError as exc:
            print(f"cronstampede: {exc}", file=sys.stderr)
            return 2
    if args.command == "explain":
        fields = args.expr.split()
        try:
            schedule = Schedule(fields)
        except FieldError as exc:
            print(f"cronstampede: {exc}", file=sys.stderr)
            return 2
        eff_tz = tz or ZoneInfo("UTC")
        eff_start = (start.astimezone(eff_tz) if start
                     else datetime.now(eff_tz))
        runs = next_runs(schedule, eff_start, max(args.next, 0))
        result = {
            "tool": TOOL, "version": VERSION, "expr": args.expr,
            "explain": explain(schedule),
            "timezone": str(eff_tz),
            "next_runs": [r.isoformat() for r in runs],
        }
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{args.expr} - {result['explain']} [{eff_tz}]")
            if runs:
                print("next: " + ", ".join(result["next_runs"]))
            else:
                print("next: never (within 4 years)")
        return 0 if runs else 1
    # audit
    try:
        with open(args.file, "r", encoding="utf-8",
                  errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"cronstampede: cannot read {args.file}: {exc.strerror or exc}",
              file=sys.stderr)
        return 2
    if args.next < 0 or args.herd_threshold < 2:
        print("cronstampede: --next must be >= 0 and --herd-threshold >= 2",
              file=sys.stderr)
        return 2
    try:
        report = audit_text(
            text, tz_override=tz_override, system=args.system,
            start=start, next_count=args.next,
            herd_threshold=args.herd_threshold,
            default_tz_name=args.tz or "UTC")
    except ValueError as exc:
        print(f"cronstampede: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_text(report))
    return 1 if report["summary"]["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
