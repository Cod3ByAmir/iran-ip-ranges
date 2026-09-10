import argparse
import logging
import sys

from .pipeline import build


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m builder", description="Build the Iran IP range lists.")
    ap.add_argument("--force", action="store_true", help="publish even if the safety guards trip")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return build(force=args.force)


if __name__ == "__main__":
    sys.exit(main())
