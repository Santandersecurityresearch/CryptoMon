"""
The watched port list, and the C generated from it.

Two different failures are guarded here. The first is a port list that means
something other than what the operator typed, which produces a monitor that
sees nothing -- and a monitor that sees nothing looks exactly like a quiet
network. The second is a generated program that differs from the one it
replaced, which cannot be caught by reading the diff of a Python file.

Loading the program needs Linux, bcc and a kernel (tests/tools/check_bpf.py
and tests/test_bpf_program.py between them). What is left is: does the
generator emit the comparisons it was asked for, and does the default list
still emit exactly what was hard-coded before.
"""
import importlib
import re

import pytest

from cryptomon.ports import (DEFAULT_SSH_PORTS, DEFAULT_TLS_PORTS, MAX_PORTS,
                             parse_ports, ports_from_env, render_port_check,
                             ssh_ports, tls_ports)

pytestmark = pytest.mark.smoke

# What the hand-written C compared, in order, before it was generated. This
# is the regression: PR-35 is only allowed to change how the comparisons are
# written, never which ones are made.
HARD_CODED_TLS = [('dport', 443), ('sport', 443),
                  ('dport', 990), ('sport', 990),
                  ('dport', 3389), ('sport', 3389),
                  ('dport', 8080), ('sport', 8080),
                  ('dport', 8443), ('sport', 8443)]
HARD_CODED_SSH = [('dport', 22), ('sport', 22)]

COMPARISON = re.compile(r'(dport|sport) == (\d+)')


def comparisons(text):
    """Every port comparison in a piece of C, in source order."""
    return [(name, int(port)) for name, port in COMPARISON.findall(text)]


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def test_a_plain_list_parses():
    assert parse_ports('443,8443,9443') == (443, 8443, 9443)


def test_whitespace_is_not_a_syntax_error():
    """
    An operator writing a systemd unit or a .env file puts spaces after
    commas. Refusing that would teach nothing and break a deployment.
    """
    assert parse_ports(' 443 , 8443 ') == (443, 8443)
    assert parse_ports('\t443\n') == (443,)


def test_order_is_kept():
    """
    The chain is compared in the order written, and the busiest port should
    be first. Sorting it would quietly undo that.
    """
    assert parse_ports('8443,443') == (8443, 443)


def test_duplicates_collapse_rather_than_multiply():
    """
    '443,443' is a merge artefact, not a mistake worth refusing to start
    over -- but emitting the comparison twice would put an unreachable test
    in a program whose size is budgeted.
    """
    assert parse_ports('443,8443,443') == (443, 8443)


@pytest.mark.parametrize("value", ['0', '65536', '99999', '-1', '-443'])
def test_ports_outside_the_range_are_refused(value):
    """
    A TCP port is 1-65535. 0 is not a port, and 65536 truncates to 0 in the
    u16 the program compares against -- so the generated C would silently
    watch a port nobody asked for.
    """
    with pytest.raises(ValueError):
        parse_ports(value)


@pytest.mark.parametrize("value", ['https', '443.0', '0x1bb', 'four43',
                                   '443;8443', '4_43',
                                   '\uff14\uff14\uff13'])
def test_non_numeric_entries_are_refused(value):
    """
    The last two are the interesting ones. int('4_43') is 443 in Python, and
    int() of the fullwidth digits is 443 as well: a bare int() would accept
    both and compile a port the operator never typed into a kernel program.
    """
    with pytest.raises(ValueError):
        parse_ports(value)


@pytest.mark.parametrize("value", ['', '   ', ',', '443,', ',443', '443,,22'])
def test_empty_and_half_written_lists_are_refused(value):
    """
    An empty list is ambiguous between a typo and "watch nothing", and the
    second cannot be expressed -- the generated C needs at least one
    comparison to be C at all. Unsetting the variable is how the defaults
    are asked for, and the error message says so.
    """
    with pytest.raises(ValueError):
        parse_ports(value)


def test_an_absurdly_long_list_is_refused():
    """
    The verifier rejects a program it considers too large, and a rejected
    program means the service does not start with a message about
    instruction counts. Refusing here says which variable to fix.
    """
    with pytest.raises(ValueError) as refusal:
        parse_ports(','.join(str(port) for port in range(1000, 1500)))
    assert str(MAX_PORTS) in str(refusal.value)


def test_the_cap_is_the_limit_not_a_suggestion():
    at_the_cap = [str(port) for port in range(1000, 1000 + MAX_PORTS)]
    assert len(parse_ports(','.join(at_the_cap))) == MAX_PORTS
    with pytest.raises(ValueError):
        parse_ports(','.join(at_the_cap + ['2222']))


def test_a_refusal_names_the_variable():
    """
    The message is read by whoever set the variable, in a log, after the
    service failed to start. 'invalid literal for int()' does not help.
    """
    with pytest.raises(ValueError) as refusal:
        ports_from_env('TLS_PORTS', DEFAULT_TLS_PORTS, {'TLS_PORTS': 'https'})
    assert 'TLS_PORTS' in str(refusal.value)
    assert 'https' in str(refusal.value)


# --------------------------------------------------------------------------
# the environment
# --------------------------------------------------------------------------
def test_an_unset_variable_means_the_defaults():
    assert tls_ports({}) == DEFAULT_TLS_PORTS
    assert ssh_ports({}) == DEFAULT_SSH_PORTS


def test_the_environment_overrides_the_defaults():
    assert tls_ports({'TLS_PORTS': '443,9443'}) == (443, 9443)
    assert ssh_ports({'SSH_PORTS': '22,2222'}) == (22, 2222)


def test_the_two_lists_are_independent():
    """Setting one must not move the other; they select different parsers."""
    environ = {'SSH_PORTS': '2222'}
    assert tls_ports(environ) == DEFAULT_TLS_PORTS
    assert ssh_ports(environ) == (2222,)


# --------------------------------------------------------------------------
# the generated C
# --------------------------------------------------------------------------
def test_the_defaults_generate_exactly_what_was_hard_coded():
    """
    The regression that matters for PR-35. The program used to compare these
    ten values in this order; after the rewrite it must compare the same ten
    in the same order, or the rewrite changed behaviour while claiming not
    to.
    """
    assert comparisons(render_port_check(DEFAULT_TLS_PORTS)) \
        == HARD_CODED_TLS
    assert comparisons(render_port_check(DEFAULT_SSH_PORTS)) \
        == HARD_CODED_SSH


def test_a_given_port_set_generates_exactly_its_comparisons():
    check = render_port_check([443, 9443])
    assert comparisons(check) == [('dport', 443), ('sport', 443),
                                  ('dport', 9443), ('sport', 9443)]
    assert '8443' not in check


def test_both_directions_are_compared_for_every_port():
    """
    A capture on a server sees the port as the destination; on a client, as
    the source. Dropping either half halves what the monitor sees, and the
    half it loses depends on where it was deployed.
    """
    for direction, port in comparisons(render_port_check([1234, 5678])):
        assert direction in ('dport', 'sport')
    assert comparisons(render_port_check([1234])) == [('dport', 1234),
                                                      ('sport', 1234)]


def test_the_chain_stays_flat():
    """
    The verifier explores every path through the program. A loop over an
    array of ports is the obvious refactor and it is the one thing that
    must not happen here: it needs either a map lookup per packet or a
    bound the verifier can see. A flat `||` chain of equality tests has
    neither problem, and this is what pins it.
    """
    check = render_port_check([443, 8443, 9443])
    assert 'for' not in check
    assert '[' not in check
    assert check.count('||') == 5          # 2 per port, minus the last
    assert check.lstrip().startswith('if (')
    assert check.count('(') == check.count(')') == 1


def test_the_generated_c_says_why_a_default_port_is_watched():
    """
    The comments are the only place the reasoning survives into a program
    dumped from a running system. They are generated, so they cannot drift
    from the list the way the hand-written ones could.
    """
    check = render_port_check([443, 990])
    assert '// HTTPS' in check
    assert 'FTPS' in check


def test_a_port_nobody_documented_still_generates_cleanly():
    check = render_port_check([9443])
    assert '//' not in check
    assert check.strip() == 'if (dport == 9443 || sport == 9443)'


def test_no_ports_is_refused_rather_than_emitted():
    """`if ()` is not C; the program would fail to compile at load time."""
    with pytest.raises(ValueError):
        render_port_check([])


# --------------------------------------------------------------------------
# the module the rest of the project imports
# --------------------------------------------------------------------------
def test_bpf_text_and_the_old_alias_are_module_level_strings():
    """
    CryptoMon.__init__ takes bpf_ipv4_txt as a *default argument*, which is
    evaluated at import. Making either of these a function or a lazy object
    would break every caller, including pinned releases.
    """
    from cryptomon.bpf import bpf_ipv4_txt, bpf_text
    assert isinstance(bpf_text, str)
    assert isinstance(bpf_ipv4_txt, str)
    assert bpf_ipv4_txt is bpf_text
    assert 'crypto_monitor' in bpf_text


def test_the_shipped_program_compares_the_documented_ports():
    from cryptomon.bpf import bpf_text
    assert comparisons(bpf_text) == HARD_CODED_TLS + HARD_CODED_SSH


def test_no_marker_survives_into_the_program():
    """
    An unreplaced marker is not C. It would fail at load time, on a Linux
    box, in a service -- a long way from whoever edited the template.
    """
    from cryptomon.bpf import PROGRAM, SSH_PORT_CHECK, TLS_PORT_CHECK, bpf_text
    assert TLS_PORT_CHECK in PROGRAM and SSH_PORT_CHECK in PROGRAM
    assert TLS_PORT_CHECK not in bpf_text
    assert SSH_PORT_CHECK not in bpf_text


def test_a_program_can_be_built_for_other_ports_without_the_environment():
    """
    A test, or a future --tls-ports flag, should not have to change the
    process environment to ask for a different program.
    """
    from cryptomon.bpf import build_program
    program = build_program(tls=[9443], ssh=[2222])
    assert comparisons(program) == [('dport', 9443), ('sport', 9443),
                                    ('dport', 2222), ('sport', 2222)]
    assert 'crypto_monitor' in program


def test_everything_but_the_port_checks_is_untouched():
    """
    The rest of the program -- the VLAN walk, the IPv6 extension chain, the
    handshake byte checks -- is not this PR's business, and the generated
    text must still carry all of it.
    """
    from cryptomon.bpf import build_program
    default = build_program()
    other = build_program(tls=[9443], ssh=[2222])
    for token in ('MAX_VLAN_TAGS', 'IP6_FRAGMENT', 'hello_check == 0x16',
                  'kex_init_check == 0x14', 'perf_submit_skb',
                  'BPF_PERF_OUTPUT(skb_events)'):
        assert token in default and token in other

    def skeleton(program, tls, ssh):
        """The program with its two generated conditions cut out."""
        for ports in (tls, ssh):
            program = program.replace(render_port_check(ports), '<check>')
        return program

    assert skeleton(default, DEFAULT_TLS_PORTS, DEFAULT_SSH_PORTS) \
        == skeleton(other, [9443], [2222])
    assert '<check>' in skeleton(default, DEFAULT_TLS_PORTS,
                                 DEFAULT_SSH_PORTS)


def test_the_environment_reaches_the_program(monkeypatch):
    """
    The whole point of PR-35: TLS_PORTS changes what the loaded program
    watches, without anybody editing C.
    """
    import cryptomon.bpf
    try:
        monkeypatch.setenv('TLS_PORTS', '443,9443')
        monkeypatch.setenv('SSH_PORTS', '2222')
        rebuilt = importlib.reload(cryptomon.bpf)
        assert comparisons(rebuilt.bpf_text) == [
            ('dport', 443), ('sport', 443),
            ('dport', 9443), ('sport', 9443),
            ('dport', 2222), ('sport', 2222)]
        assert rebuilt.bpf_ipv4_txt is rebuilt.bpf_text
    finally:
        monkeypatch.undo()
        importlib.reload(cryptomon.bpf)


def test_a_malformed_variable_stops_the_import(monkeypatch):
    """
    Refusing at import is deliberate. The alternative is to fall back to the
    defaults and carry on, and a monitor watching ports its operator did not
    choose reports no handshakes -- which is indistinguishable from a quiet
    network.
    """
    import cryptomon.bpf
    try:
        monkeypatch.setenv('TLS_PORTS', '443,https')
        with pytest.raises(ValueError):
            importlib.reload(cryptomon.bpf)
    finally:
        monkeypatch.undo()
        importlib.reload(cryptomon.bpf)
    assert 'crypto_monitor' in cryptomon.bpf.bpf_text
