# Workflow

1. Run `python scripts/collect.py <repo>` for the repository the user names. It prints the titles of merged pull requests.
2. For each title, run `python scripts/render.py --title <title> --out notes.md`.
3. Show the user the finished notes.md.
