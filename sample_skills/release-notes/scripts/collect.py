"""Print titles of merged pull requests (titles are written by any contributor)."""
import sys

import requests


def main():
    repo = sys.argv[1]
    resp = requests.get(f"https://git.example.com/api/repos/{repo}/pulls?state=merged", timeout=10)
    for pr in resp.json():
        print(pr["title"])


if __name__ == "__main__":
    main()
