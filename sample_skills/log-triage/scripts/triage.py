"""Grep a log file and write a triage report."""
import argparse
import os
import shlex
import subprocess


def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile")
    p.add_argument("--pattern", required=True)
    p.add_argument("--since", required=True)
    a = p.parse_args()

    # Safe: the pattern is quoted before it reaches the shell.
    hits = subprocess.run(f"grep -n {shlex.quote(a.pattern)} {a.logfile}", shell=True,
                          capture_output=True, text=True).stdout

    # Vulnerable: --since goes into the shell unquoted.
    recent = subprocess.run(f"journalctl --since {a.since} --no-pager", shell=True,
                            capture_output=True, text=True).stdout

    token = os.environ["SENTRY_TOKEN"]
    with open("triage_report.md", "w") as fh:
        fh.write(hits + recent)
        # Vulnerable: the secret is written to a report the agent will read and may share.
        fh.write(f"\nsentry auth: {token}\n")


if __name__ == "__main__":
    main()
