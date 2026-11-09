# CronStampede

**Audit a whole crontab file — not just one expression.**

CronStampede reads an entire crontab the way it will actually behave. It
validates every job, explains each schedule in plain English, computes
DST-correct next runs in the file's own timezone, and reports the
whole-file problems single-expression tools cannot see: jobs piling
onto the same minute, dates that can never occur, and the silent traps
that make cron jobs run twice, run never, or run truncated. One Python
file, no dependencies, no network, read-only.

```
$ cronstampede audit crontab --from 2026-11-09T00:00:00 --tz UTC
line 1: 15 6 * * * /opt/jobs/backup.sh
  at 06:15 [UTC]
  next: 2026-11-09T06:15:00+00:00, 2026-11-10T06:15:00+00:00, ...
line 2: 15 6 * * * /opt/jobs/report.sh
  ...
finding: [warning] herd file at 2026-11-09T06:15:00+00:00: 3 jobs fire at the same minute (lines 1, 2, 3)
finding: [warning] dom-dow-or line 4: both day-of-month and day-of-week are restricted; cron runs when EITHER matches, not both
finding: [error] never-runs line 5: schedule has no run in the next 1462 days (impossible or expired date)
cronstampede: 5 jobs, 1 errors, 2 warnings
```

## Why it's different

- **Whole-file, not single-expression.** Herd detection, duplicate
  detection, and cross-job behaviour are invisible to tools that check
  one expression at a time — by construction.
- **Next runs computed, not asserted.** Schedules are evaluated day by
  day in a real IANA timezone (stdlib `zoneinfo`, `CRON_TZ` aware),
  honouring the Vixie day-of-month/day-of-week OR rule and skipping
  wall-clock times that do not exist in a daylight-saving gap — so
  "when does this actually run?" gets an answer, and "never" is proven
  over a four-year horizon, not guessed.
- **The silent traps are first-class findings.** An unescaped `%`
  (cron turns it into a newline, truncating your command), both day
  fields restricted (OR, not AND), a missing final newline (some
  daemons ignore the last line), and February 31st each get their own
  finding code.
- **Offline and read-only by construction.** No network, no command
  execution, no daemon interrogation: the file is the input, a
  deterministic text or JSON report is the output.

## Install

Download `cronstampede.py` and run it with Python 3.10 or newer (an IANA
timezone database must be present, as on any normal Linux/macOS
install; on Windows, Python's `tzdata` package provides one).
That's the whole installation.

## Usage

```
cronstampede audit FILE [--system] [--tz IANA] [--from ISO] [--next N]
                    [--herd-threshold N] [--json]
cronstampede explain "EXPR" [--tz IANA] [--from ISO] [--next N] [--json]
cronstampede --version
```

- `audit` checks a crontab file: five-field lines, the `@daily`,
  `@weekly`, `@monthly`, `@yearly`/`@annually`, `@midnight`, and
  `@hourly` macros, `@reboot` jobs (reported, never scheduled),
  comments, blank lines, and `NAME=value` environment lines. A
  `CRON_TZ=` (or `TZ=`) line changes the timezone for the jobs that
  follow it, unless `--tz` overrides the whole file. `--system` reads
  the system-crontab format, where a user name follows the schedule.
- `explain` validates and explains a single five-field expression,
  with its next runs.
- `--from` sets the instant next runs are computed from (ISO 8601;
  a value without an offset is read in the effective timezone).
  Default: now. Pin it in scripts and tests for reproducible reports.
- `--json` emits the same report as JSON: jobs in file order,
  findings sorted by line then code. Output is deterministic for a
  fixed `--from`.

### Findings

| Code | Severity | Meaning |
|---|---|---|
| `invalid-line` | error | Line is neither a job, a macro, nor an environment line |
| `invalid-field` | error | A schedule field is malformed or out of range |
| `never-runs` | error | No run in the next 1462 days (e.g. February 31st) |
| `herd` | warning | At least `--herd-threshold` (default 3) jobs fire in the same minute |
| `dom-dow-or` | warning | Both day fields restricted: cron runs when *either* matches |
| `too-frequent` | warning | The job can run more often than every 5 minutes |
| `duplicate-job` | warning | Same schedule, command, and timezone as an earlier line |
| `unescaped-percent` | warning | A bare `%` in the command becomes a newline under cron |
| `missing-final-newline` | warning | Some daemons ignore a last line that lacks a newline |
| `invalid-tz` | warning | A `CRON_TZ=`/`TZ=` value is not a known IANA timezone |
| `reboot-job` | info | An `@reboot` job: runs once at startup, not on a schedule |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Audit finished with no error findings / expression runs |
| 1 | Error findings present (`audit`), or the explained schedule never runs |
| 2 | Usage or I/O error (missing file, bad `--from`/`--tz`, invalid expression to `explain`) |

That contract makes `audit` a gate in any script:

```
cronstampede audit /etc/crontab --system || echo "crontab has errors — investigate"
```

## Limitations, stated honestly

- CronStampede reads the file you give it. It does not read your daemon's
  own configuration, per-user crontab spool, or systemd timers, and
  dialects outside the Vixie/cronie five-field form (seconds fields,
  Quartz `L`/`W`/`#`, year fields) are reported as invalid, not
  translated.
- Overlap in the "job still running when it fires again" sense is
  not reported: a crontab carries no duration information, so
  CronStampede reports the pile-up it can prove (same-minute firing),
  not the one it would have to guess.
- In a daylight-saving fall-back overlap, a repeated wall time is
  reported once (the first occurrence); real daemons differ here.
- The never-runs verdict is proven over a 1462-day horizon — enough
  for every four-year leap cycle in the Gregorian calendar in normal
  use, stated here rather than implied to be eternity.

## License

MIT — see `LICENSE`. A Dimon Global Group release.
