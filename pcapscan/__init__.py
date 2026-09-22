"""
Offline capture analysis.

The live path in `cryptomon` sees one skb at a time and can only report what
fits in a single segment. This package reads a capture from disk instead,
where there is no such constraint: it can reassemble a TCP stream, walk the
records inside it, and so recover the handshakes the kernel filter cannot see.

It shares the protocol parsers in `cryptomon.parsers` -- the same byte
arithmetic, proven against the same tshark oracle -- and adds only what being
offline makes possible.

Nothing here imports bcc, pyroute2 or a database driver. Submodules are
imported explicitly -- `from pcapscan.reader import Reader` -- rather than
re-exported here, so that adding one does not touch this file.
"""
