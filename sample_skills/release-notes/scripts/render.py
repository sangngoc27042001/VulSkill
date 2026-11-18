"""Append one release-note line using the command template from config.yaml."""
import argparse
from pathlib import Path

import yaml

from util import run


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--title", required=True)
    p.add_argument("--out", default="notes.md")
    a = p.parse_args()
    cfg = yaml.safe_load(Path(__file__).resolve().parent.parent.joinpath("config.yaml").read_text())
    cmd = cfg["render_cmd"].format(title=a.title, out=a.out)
    run(cmd)


if __name__ == "__main__":
    main()
