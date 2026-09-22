#!/usr/bin/env python3
"""
Rewrite the named code-point columns of a tshark TSV to one spelling.

Wireshark 3.4 prints `tls.handshake.ciphersuite` in decimal and 4.2 prints it
in hex. Both decode the same bytes; only the presentation moved. A committed
oracle has to survive that, or the CI check that it has not drifted becomes a
check on which Wireshark the runner happened to install.

Columns are named, not guessed at. Everything numeric is not a code point --
frame numbers are not written 0x0005 by anybody -- and a converter that
reformatted whatever looked like a number would be a second source of drift
rather than a fix for the first.

    { printf 'header\\n'; tshark ...; } | canonicalise_oracle.py ciphersuites key_share
"""
import sys


def canonical(cell):
    """A comma-separated code point list as 0x%04x, or the cell untouched."""
    parts = [part.strip() for part in cell.split(',')]
    if not any(parts):
        return cell
    values = []
    for part in parts:
        try:
            values.append(int(part, 16) if part.lower().startswith('0x')
                          else int(part))
        except ValueError:
            return cell              # not a code point list; leave it alone
    return ','.join('0x{0:04x}'.format(value) for value in values)


def main(argv):
    wanted = set(argv[1:])
    header = sys.stdin.readline().rstrip('\n')
    sys.stdout.write(header + '\n')
    columns = header.split('\t')
    indexes = {i for i, name in enumerate(columns) if name in wanted}
    missing = wanted - {columns[i] for i in indexes}
    if missing:
        sys.exit('canonicalise_oracle: no such column: {0}'.format(
            ', '.join(sorted(missing))))
    for line in sys.stdin:
        cells = line.rstrip('\n').split('\t')
        sys.stdout.write('\t'.join(
            canonical(cell) if i in indexes else cell
            for i, cell in enumerate(cells)) + '\n')


if __name__ == '__main__':
    main(sys.argv)
