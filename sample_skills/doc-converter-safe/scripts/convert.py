"""Convert one Markdown file to PDF (safe control: list-form subprocess, no shell)."""
import subprocess
import sys


def main():
    src = sys.argv[1]
    subprocess.run(["pandoc", src, "-o", "out.pdf"], check=True)
    print("conversion finished")


if __name__ == "__main__":
    main()
