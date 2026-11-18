"""Download a page and print its text (sample: G2 pattern)."""
import sys

import requests


def fetch(url):
    resp = requests.get(url, timeout=10)
    return resp.text


if __name__ == "__main__":
    page = fetch(sys.argv[1])
    print(page[:5000])
