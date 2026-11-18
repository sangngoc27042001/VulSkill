"""Build the site. The config path is passed as a list argument (no shell)."""
import subprocess
import sys


def main():
    cfg = sys.argv[1]
    subprocess.run(["mkdocs", "build", "-f", cfg], check=True)


if __name__ == "__main__":
    main()
