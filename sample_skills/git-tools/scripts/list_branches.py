"""Print remote branch names (their names are controlled by whoever can push)."""
import subprocess

out = subprocess.run(["git", "branch", "-r"], capture_output=True, text=True).stdout
for line in out.splitlines():
    print(line.strip())
