"""
Which TCP ports the live monitor watches, and how that reaches the C.

Until this module the answer was five comparisons in the middle of an eBPF
program: changing which ports were monitored meant editing C in a string
literal and hoping it still compiled on the next kernel. That is the live
half of issue #13. The port list is now Python data, overridable from the
environment, and the C is generated from it.

**None of these numbers is cryptography.** They are conventions about where
TLS is usually spoken, and the corpus says exactly that: of 1260 sessions
across the twelve captures, 1248 are to port 443 and the remaining 12 are to
ephemeral ports (8 of them 53443). Nothing in the corpus touches 990, 3389,
8080, 8443 or 22. So the defaults beyond 443 are not measured, they are
convention -- which is the argument for making the list configurable rather
than for arguing about a better list.

The offline parser has no port filter at all: it looks at every TCP stream
and decides from the bytes. The live monitor cannot, because the filter is
what keeps it from copying every packet on the interface to userspace. That
asymmetry is why those 12 ephemeral-port sessions exist in the offline
numbers and could never appear in the live ones.

What the generated C must stay: a flat `||` chain of equality tests. The
verifier walks every path in the program, so the shape of this expression is
not a style question -- see MAX_PORTS.
"""
import os

# The environment variable names. No prefix, matching fapi/config, where the
# field name *is* the variable name -- adding one here would mean two
# conventions in one deployment.
TLS_PORTS_ENV = 'TLS_PORTS'
SSH_PORTS_ENV = 'SSH_PORTS'

DEFAULT_TLS_PORTS = (443, 990, 3389, 8080, 8443)
DEFAULT_SSH_PORTS = (22,)

# One line per port, carried into the generated C so that a program read out
# of a running system still says why it watches what it watches.
#
# 443 is the only one the corpus justifies. The others:
#
#   990   FTPS wraps the FTP control channel in TLS from the first byte
#         (RFC 4217 implicit mode), so a handshake is what appears there.
#   3389  RDP negotiates TLS inside its X.224 connection request, and has
#         done since Windows Server 2003 SP1. The handshake is a real TLS
#         handshake, so the same parser reads it.
#   8443  the conventional alternative HTTPS port.
#   8080  the weak one, and it is honest to say so. 8080 is the conventional
#         alternative *plaintext* HTTP port; TLS there is a local habit, not
#         a registration. It stays because removing a default changes what
#         existing deployments see, and because the cost of the wrong guess
#         is bounded: the program still requires a record beginning 0x16
#         0x03 0x0[1-4] before it submits anything, so plaintext HTTP on
#         8080 produces no events. It is not free, though -- every packet on
#         a watched port takes the `return -1` branch instead of returning
#         TC_ACT_OK immediately. On a host with busy 8080 traffic that is now
#         one environment variable away from being fixed.
#   22    the registered SSH port, and in practice the only one -- but sshd
#         on 2222 is common enough that SSH_PORTS has to exist.
PORT_NOTES = {
    443: 'HTTPS',
    990: 'FTPS control channel (RFC 4217)',
    3389: 'RDP, which negotiates TLS',
    8080: 'alternative HTTP; see ports.py',
    8443: 'alternative HTTPS',
    22: 'SSH (RFC 4253)',
}

MIN_PORT = 1
MAX_PORT = 65535

# A ceiling on each list, because the verifier has one on the program. Every
# port becomes two comparisons in a flat `||` chain; a chain long enough to
# push the program past the instruction limit is rejected at load time, and
# a rejected program means the monitor does not start -- with a diagnostic
# from the kernel about instruction counts rather than from here about the
# port list.
#
# This is not measured, and saying so matters: counting instructions needs
# Linux, bcc and a kernel, which is what tests/tools/check_bpf.py is for. So
# the cap is chosen to be far enough below the oldest ceiling that the chain
# cannot be the cause. Kernels before 5.2 cap a program at BPF_MAXINSNS =
# 4096 instructions; a comparison pair costs on the order of eight. Sixty-
# four ports is then around 512 instructions on top of a program that is a
# couple of hundred -- an eighth of the oldest ceiling and a rounding error
# against the million-instruction budget of anything current. Someone who
# needs more than 64 ports on one interface is describing a packet capture,
# not a handshake monitor.
MAX_PORTS = 64


def parse_ports(value, source='port list'):
    """
    A comma-separated port list -> a tuple of ints. Raises on anything else.

    Deliberately strict, because the failure it prevents is silent: a
    monitor that watches the wrong ports reports no handshakes, and no
    handshakes looks exactly like a quiet network. Every rejection names
    `source` and the offending text so the operator can see which variable
    to fix.

    Note the ASCII digit test rather than a bare int(): int() accepts
    underscores as digit separators, so int('4_43') is 443, and it accepts
    non-ASCII digits, so int('\uff14\uff14\uff13') is 443 too. A port
    list is operator input that ends up compiled into a kernel program; it
    should mean what it looks like or be refused.
    """
    if value is None:
        raise ValueError('{0}: no value'.format(source))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            # Ambiguous between "I meant to type something" and "watch
            # nothing", and the second cannot be expressed: the generated C
            # needs at least one comparison to be C at all. Unsetting the
            # variable is how you ask for the defaults.
            raise ValueError(
                '{0}: empty. Unset the variable to use the defaults.'
                .format(source))
        items = text.split(',')
    else:
        # A list of ints, for a caller that has one already -- a future
        # --tls-ports flag, say. Everything else is refused here rather than
        # raising TypeError somewhere less obvious.
        try:
            items = list(value)
        except TypeError:
            raise ValueError(
                '{0}: {1!r} is not a port list'.format(source, value)) \
                from None
    ports = []
    for item in items:
        item = str(item).strip()
        if not item:
            raise ValueError(
                '{0}: empty entry in {1!r} -- every comma must separate two '
                'port numbers'.format(source, value))
        if not (item.isascii() and item.isdigit()):
            raise ValueError(
                '{0}: {1!r} is not a port number'.format(source, item))
        port = int(item)
        if not MIN_PORT <= port <= MAX_PORT:
            raise ValueError(
                '{0}: port {1} is outside {2}-{3}'.format(
                    source, port, MIN_PORT, MAX_PORT))
        if port not in ports:
            # Duplicates are dropped rather than refused: they compile to a
            # comparison that can never be reached twice, and "443,443" is a
            # merge artefact, not a mistake worth stopping a service over.
            ports.append(port)
    if not ports:
        raise ValueError(
            '{0}: no ports. Unset the variable to use the defaults.'
            .format(source))
    if len(ports) > MAX_PORTS:
        raise ValueError(
            '{0}: {1} ports, more than the {2} this program can carry past '
            'the verifier'.format(source, len(ports), MAX_PORTS))
    return tuple(ports)


def ports_from_env(name, default, environ=None):
    """
    A port list from the environment, or the default when it is not set.

    Unset means "use the defaults". Set to anything unparseable raises, on
    the way in, rather than at the point where a kernel refuses the program.
    """
    environ = os.environ if environ is None else environ
    if name not in environ:
        return tuple(default)
    return parse_ports(environ[name], source=name)


def tls_ports(environ=None):
    """The TLS ports to watch: TLS_PORTS, or DEFAULT_TLS_PORTS."""
    return ports_from_env(TLS_PORTS_ENV, DEFAULT_TLS_PORTS, environ)


def ssh_ports(environ=None):
    """The SSH ports to watch: SSH_PORTS, or DEFAULT_SSH_PORTS."""
    return ports_from_env(SSH_PORTS_ENV, DEFAULT_SSH_PORTS, environ)


def render_port_check(ports, indent=4):
    """
    The `if (...)` line of C that selects these ports.

    A flat chain of `dport == P || sport == P`, one port per line, exactly
    the shape the hand-written program had. The shape is load-bearing: the
    verifier explores every path through the program, and a loop over a port
    array -- the obvious refactor -- either needs a map lookup per packet or
    a bound the verifier can see, both of which cost more than the chain
    they replace. The chain is also what makes the generated program
    readable next to the one it replaced, which is the only way to be sure
    a rewrite changed nothing.

    Returns the condition with its `if (` and closing `)`, because the
    continuation lines are aligned under the parenthesis and only this
    function knows where it is.
    """
    ports = tuple(ports)
    if not ports:
        raise ValueError('no ports to watch: the C would not compile')
    pad = ' ' * indent
    comparisons = ['dport == {0} || sport == {0}'.format(port)
                   for port in ports]
    column = max(len(text) for text in comparisons) + len(' ||')
    lines = []
    for index, (port, comparison) in enumerate(zip(ports, comparisons)):
        last = index == len(ports) - 1
        text = comparison + (')' if last else ' ||')
        note = PORT_NOTES.get(port)
        if note:
            text = '{0:<{1}}  // {2}'.format(text, column, note)
        lines.append('{0}{1}{2}'.format(
            pad, 'if (' if index == 0 else '    ', text))
    return '\n'.join(lines)
