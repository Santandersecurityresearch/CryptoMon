"""Entry point for `python -m pcapscan`."""
import sys

from pcapscan.cli import main

if __name__ == '__main__':
    sys.exit(main())
