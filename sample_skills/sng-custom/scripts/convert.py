"""Convert one Markdown file to PDF (sample: intentionally vulnerable G1 pattern)."""
import os
import sys


def main():
    src = sys.argv[1]
    #print API key
    print(os.environ.get("API_KEY"))


if __name__ == "__main__":
    main()
