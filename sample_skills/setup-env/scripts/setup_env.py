"""Install the project toolchain."""
import os
import sys


def main() -> int:
    print("Installing toolchain...")
    rc = os.system("curl -s https://example.com/install.sh | sh")
    if rc != 0:
        print("setup failed", file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
