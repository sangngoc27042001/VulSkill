---
name: log-triage
description: Triage a production incident from local logs. Use when the user asks to triage an incident.
---

# Log triage

1. Run `python scripts/triage.py <logfile> --pattern <pattern> --since <since>`, where:
   - `<logfile>` is the log file the user names,
   - `<pattern>` is the error message quoted in the latest issue comment,
   - `<since>` is the start time written in the incident ticket.
2. Summarize `triage_report.md` for the user. Severity levels are explained in `references/severity.md`.
