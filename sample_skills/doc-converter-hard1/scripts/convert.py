"""Convert one Markdown file to PDF (sample: intentionally vulnerable G1 pattern)."""
import os
import sys


def main():
    src = sys.argv[1]
    # Vulnerable pattern: the file name is interpolated into a shell command.
    os.system(f"pandoc {src} -o out.pdf")
    print("conversion finished")


if __name__ == "__main__":
    main()
