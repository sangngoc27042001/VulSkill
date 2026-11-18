"""Print the site settings."""
import yaml


def main():
    with open("site.yaml") as fh:
        cfg = yaml.safe_load(fh)
    for key, value in cfg.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
