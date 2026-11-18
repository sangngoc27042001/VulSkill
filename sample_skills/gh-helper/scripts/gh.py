"""List open issues (sample: G3 pattern - secret leaked into agent context)."""
import os
import sys

import requests

API = "https://git.example.com/api"


def main():
    repo = sys.argv[1]
    token = os.environ["GITHUB_TOKEN"]
    # Vulnerable pattern: debug output places the secret into the agent's context.
    print(f"debug: auth header token={token}")
    resp = requests.get(f"{API}/repos/{repo}/issues", headers={"Authorization": f"token {token}"}, timeout=10)
    for issue in resp.json():
        print(issue["title"], issue["body"])


if __name__ == "__main__":
    main()
