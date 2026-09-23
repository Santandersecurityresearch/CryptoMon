"""
The deployment artifacts in deploy/, and the one application behaviour they
depend on.

Two different kinds of check live here, for the same reason.

**The prefix.** Serving this app at https://host/cryptomon/ rather than at a
domain root works only if the app knows it is there, because it builds
absolute URLs: fapi/app/uploads.py redirects to `request.url_for('report',
...)` after an upload, upload.html posts to action="", and FastAPI composes
the openapi.json URL that /docs fetches. When the prefix is wrong none of
that raises -- the pages render, the form submits, and the redirect lands one
level up on a 404. It is found by a user, and it looks like an application
bug. So it is pinned here with a real router, a real request and a real
Location header.

**The numbers that must agree with each other.** nginx's
client_max_body_size and the app's MAX_UPLOAD_BYTES, and nginx's
proxy_read_timeout and the app's ANALYSIS_TIMEOUT_SECONDS, are two pairs that
are configured in different files by different people. Neither disagreement
produces an error anywhere: the first makes nginx answer a large upload with
its own unstyled 413 before the application's careful mid-stream check can
run, and the second makes nginx answer 504 for an analysis that finished.
The nginx side is parsed out of deploy/nginx/ and the application side is
read from `fapi.config.settings`, so changing a default in fapi/config
breaks this file rather than a deployment.

The unit-file checks exist because of what they replace. create-service.sh
used to generate a unit containing

    Environment="DB_URL=mongodb://cryptomonUser:<password>@..."

which put a database password in a world-readable file under
/etc/systemd/system and in the output of `systemctl show`, which any user can
run.
"""
import os
import pathlib
import re

import pytest

os.environ.setdefault("DB_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "cryptomon-test")

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

import fapi.app.uploads as uploads                             # noqa: E402
from fapi.config import settings                               # noqa: E402
from pcapscan.sandbox import SandboxResult                      # noqa: E402

# Merge gate: no capture fixtures, no database, no docker, no network. The
# analyser is stubbed in the upload tests below -- what is under test is
# which URL comes back, not what is in the capture.
pytestmark = pytest.mark.smoke

REPO = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy"
NGINX_DIR = DEPLOY / "nginx"
SYSTEMD_DIR = DEPLOY / "systemd"

# The prefix these files are written for. Kept here rather than derived, so
# that a test failure names the value that was expected.
PREFIX = "/cryptomon"


# ==========================================================================
# a very small nginx parser
# ==========================================================================
def strip_comments(text):
    """
    Remove `#` comments, leaving quoted strings alone.

    Worth doing properly rather than with a line-wise regex: the log_format
    and `map` directives in cryptomon.conf hold quoted strings, and a naive
    strip would one day cut one of them in half and produce a config that
    parses to something subtly different from what these tests checked.
    """
    out = []
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            out.append(char)
            if char == "\\" and index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            out.append(char)
        elif char == "#":
            while index < len(text) and text[index] != "\n":
                index += 1
            out.append("\n")
            continue
        else:
            out.append(char)
        index += 1
    return "".join(out)


def directives(text):
    """
    Yield (name, [args]) for every simple directive in an nginx config.

    Block headers -- `server {`, `location /x {` -- are yielded too, with the
    brace dropped, because the location paths are worth asserting on. Nesting
    is not tracked: nothing here needs to know which block a directive is in,
    and a parser that claimed to would be a parser with more to get wrong.
    """
    body = strip_comments(text)
    for statement in re.split(r"[;{}]", body):
        tokens = statement.split()
        if tokens:
            yield tokens[0], tokens[1:]


def nginx_text():
    """Every shipped nginx file, concatenated. Order does not matter here."""
    parts = []
    for path in sorted(NGINX_DIR.glob("*.conf")):
        parts.append(path.read_text(encoding="utf-8"))
    assert parts, "no nginx config found under {0}".format(NGINX_DIR)
    return "\n".join(parts)


def values_of(name, text=None):
    text = nginx_text() if text is None else text
    return [args for found, args in directives(text) if found == name]


SIZE_UNITS = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
# nginx time suffixes. `m` is MINUTES here and MEGABYTES in a size, which is
# exactly why these are two functions and not one.
TIME_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400,
              "w": 604800}


def nginx_size(value):
    match = re.fullmatch(r"(\d+)([kKmMgG]?)", value)
    assert match, "not an nginx size: {0!r}".format(value)
    return int(match.group(1)) * SIZE_UNITS[match.group(2).lower()]


def nginx_time(value):
    match = re.fullmatch(r"(\d+)(ms|[smhdw]?)", value)
    assert match, "not an nginx time: {0!r}".format(value)
    return int(match.group(1)) * TIME_UNITS[match.group(2) or "s"]


# ==========================================================================
# root_path: the regression a user would otherwise find
# ==========================================================================
@pytest.fixture
def prefixed_app(tmp_path, monkeypatch):
    """
    The real upload router, mounted the way api.py mounts it, on an app that
    has been told it lives under /cryptomon.

    Built here rather than imported from api.py so that the test states the
    arrangement it is checking: root_path on the app, the router at
    /analyse, and nothing else.
    """
    monkeypatch.setattr(settings, "UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setattr(settings, "UPLOADS_ENABLED", True)
    monkeypatch.setattr(settings, "API_KEY", "")

    app = FastAPI(root_path=PREFIX)
    app.include_router(uploads.router, prefix="/analyse")
    return app


@pytest.fixture
def stub_analysis(monkeypatch):
    """
    Answer every analysis instantly with an empty but well-formed report.

    The upload route's real work is a subprocess over a capture file, which
    is neither fast nor the subject of these tests -- tests/test_uploads.py
    covers it. Patched on the uploads module rather than on pcapscan.sandbox
    because uploads.py imports the name directly.
    """
    def fake(path, limits=None, python=None):
        return SandboxResult(True, document={"meta": {}, "summary": {}},
                             elapsed=0.001)
    monkeypatch.setattr(uploads, "analyse_capture", fake)


def test_url_path_for_is_prefix_free(prefixed_app):
    """
    The router's own view of the report route carries no prefix.

    This is the half that must NOT change: root_path is added when an
    absolute URL is built, not when the route is registered. If this starts
    returning /cryptomon/analyse/... then the prefix is being applied twice
    and every generated link is /cryptomon/cryptomon/...
    """
    path = prefixed_app.url_path_for("report", report_id="a" * 32)
    assert str(path) == "/analyse/reports/{0}".format("a" * 32)


def test_form_renders_under_the_prefix(prefixed_app):
    client = TestClient(prefixed_app)
    response = client.get(PREFIX + "/analyse/")
    assert response.status_code == 200
    # action="" is what makes the form post to whatever path the browser is
    # on, which is the only reason it survives being moved under a prefix.
    # A form that grew action="/analyse/" would post outside the prefix and
    # 404, and nothing else in this suite would notice.
    assert 'action=""' in response.text


def test_unprefixed_path_is_not_served(prefixed_app):
    """
    With nginx passing the URI unchanged, a request that arrives without the
    prefix should not be routed... except that starlette removes the prefix
    with a substitution that does nothing when it is absent, so it IS
    routed.

    Asserted rather than left implicit because it is surprising, it is
    relied on (it is what lets an operator put a stripping proxy in front of
    the same configuration), and it means "/analyse/ answers" is not
    evidence that ROOT_PATH is unset.
    """
    client = TestClient(prefixed_app)
    assert client.get("/analyse/").status_code == 200


def test_redirect_after_upload_carries_the_prefix(prefixed_app,
                                                  stub_analysis):
    """
    The regression this file exists for.

    A missing root_path does not raise: the upload succeeds, the report is
    written, and the browser is sent to /analyse/reports/<id> -- one level
    above where the service lives -- where nginx answers 404. The report is
    fine. The user is told it failed.
    """
    client = TestClient(prefixed_app, follow_redirects=False)
    response = client.post(
        PREFIX + "/analyse/",
        files={"capture": ("whatever.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 64,
                           "application/octet-stream")},
        data={"as_json": "false"})

    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert re.fullmatch(
        r"http://testserver" + re.escape(PREFIX)
        + r"/analyse/reports/[0-9a-f]{32}", location), location


def test_redirect_scheme_follows_x_forwarded_proto(prefixed_app,
                                                   stub_analysis):
    """
    The redirect is an absolute URL, so its scheme comes from the ASGI
    scope -- which uvicorn sets from X-Forwarded-Proto and only when
    --proxy-headers is on and the connection is from a trusted address.

    TestClient cannot exercise uvicorn's middleware, so the scope is set
    directly. What this pins is that nothing in the application overrides
    the scheme on the way out: if it did, deploy/nginx/proxy-to-cryptomon
    .conf's X-Forwarded-Proto header would be pointless and every
    post-upload redirect on an https site would be http://.
    """
    client = TestClient(prefixed_app, follow_redirects=False,
                        base_url="https://cryptomon.example.org")
    response = client.post(
        PREFIX + "/analyse/",
        files={"capture": ("whatever.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 64,
                           "application/octet-stream")},
        data={"as_json": "false"})
    assert response.status_code == 303
    assert response.headers["location"].startswith(
        "https://cryptomon.example.org" + PREFIX + "/analyse/reports/")


def test_settings_carry_a_root_path():
    """
    ROOT_PATH has to be a setting, not a command-line flag.

    api.py is the documented entry point and calls uvicorn.run()
    programmatically, so `uvicorn --root-path` is not available to it. And
    the header route does not exist: uvicorn 0.30's proxy-header middleware
    handles X-Forwarded-For and X-Forwarded-Proto and has no notion of a
    prefix, so nothing arriving on the wire carries one.

    If this fails, the change in fapi/config/__init__.py that adds
    ROOT_PATH has not been applied -- see deploy/README.md.
    """
    assert hasattr(settings, "ROOT_PATH"), (
        "fapi.config.Settings has no ROOT_PATH; the subpath deployment in "
        "deploy/nginx/cryptomon.conf cannot work without it")
    assert settings.ROOT_PATH == "" or settings.ROOT_PATH.startswith("/")


def test_api_passes_root_path_to_fastapi():
    """
    And it has to reach FastAPI. A ROOT_PATH nothing reads is worse than no
    ROOT_PATH at all: the operator sets it, the deployment still generates
    unprefixed URLs, and the setting is the first place they will stop
    looking.
    """
    import api
    assert api.app.root_path == settings.ROOT_PATH, (
        "api.py must build FastAPI(root_path=settings.ROOT_PATH)")


@pytest.mark.parametrize("bad", ["cryptomon", "/cryptomon/", "/a.b",
                                 "/x+y", "//double"])
def test_root_path_rejects_anything_but_a_plain_path(bad):
    """
    starlette 0.37.2 strips the prefix with

        re.sub(r"^" + root_path, "", scope["path"])

    -- interpolated into a regular expression with no re.escape. A ROOT_PATH
    containing a regex metacharacter therefore matches paths it was never
    meant to match. `/cryptomon/` with its trailing slash is a different
    failure and just as common: it makes every stripped path lose its
    leading slash and match nothing.

    Normalising and refusing at startup turns both into an error message.
    """
    from fapi.config import ServerSettings
    if bad == "/cryptomon/":
        # Normalised rather than refused: a trailing slash is a typo with an
        # obvious intent, and guessing it is better than refusing to start.
        assert ServerSettings(ROOT_PATH=bad).ROOT_PATH == "/cryptomon"
        return
    with pytest.raises(Exception):
        ServerSettings(ROOT_PATH=bad)


# ==========================================================================
# nginx and the application must agree about two numbers
# ==========================================================================
def test_client_max_body_size_admits_a_full_size_upload():
    """
    The brief's floor: nginx must accept at least MAX_UPLOAD_BYTES.

    Below it, nginx refuses first with its own unstyled HTML 413 and the
    message fapi/app/uploads.py composes -- which names the limit and
    suggests `editcap -c` -- is never reached.
    """
    sizes = [nginx_size(args[0]) for args in values_of("client_max_body_size")]
    assert sizes, "no client_max_body_size in deploy/nginx/"
    assert max(sizes) >= settings.MAX_UPLOAD_BYTES, (
        "largest client_max_body_size is {0} but MAX_UPLOAD_BYTES is {1}; "
        "nginx would reject a legal upload before the app sees it"
        .format(max(sizes), settings.MAX_UPLOAD_BYTES))


def test_client_max_body_size_has_multipart_headroom():
    """
    And strictly above it, which is a different claim.

    nginx measures the whole request body: the multipart boundaries, each
    part's headers, and the `as_json` form field. The application measures
    only the file. At exactly MAX_UPLOAD_BYTES of capture the two disagree
    by a few hundred bytes, in the direction that gives the user nginx's
    error page instead of the application's.
    """
    sizes = [nginx_size(args[0]) for args in values_of("client_max_body_size")]
    assert max(sizes) > settings.MAX_UPLOAD_BYTES, (
        "client_max_body_size must exceed MAX_UPLOAD_BYTES, not equal it")


def test_a_small_default_body_size_applies_elsewhere():
    """
    The large limit belongs only to the upload route. /data/ hands its body
    to pydantic; inheriting 257m everywhere would let one POST there buy a
    quarter of a gigabyte of parsing.
    """
    sizes = [nginx_size(args[0]) for args in values_of("client_max_body_size")]
    assert len(sizes) >= 2, (
        "expected a small server-wide client_max_body_size as well as the "
        "large one on the upload location")
    assert min(sizes) < settings.MAX_UPLOAD_BYTES


def test_proxy_read_timeout_outlasts_an_analysis():
    """
    The upload POST returns nothing at all until the analysis finishes, so
    proxy_read_timeout is what nginx will wait. Below
    ANALYSIS_TIMEOUT_SECONDS it answers 504 for work the service completed:
    the report exists, the user is told it failed, and the retry costs
    another subprocess.
    """
    timeouts = [nginx_time(args[0]) for args in values_of("proxy_read_timeout")]
    assert timeouts, "no proxy_read_timeout in deploy/nginx/"
    assert min(timeouts) > settings.ANALYSIS_TIMEOUT_SECONDS, (
        "smallest proxy_read_timeout is {0}s but ANALYSIS_TIMEOUT_SECONDS "
        "is {1}".format(min(timeouts), settings.ANALYSIS_TIMEOUT_SECONDS))


def test_proxy_send_timeout_covers_a_full_upload():
    """With request buffering off, this is how long the client has to send."""
    timeouts = [nginx_time(args[0]) for args in values_of("proxy_send_timeout")]
    assert timeouts and min(timeouts) >= settings.ANALYSIS_TIMEOUT_SECONDS


def test_uploads_are_not_spooled_twice():
    """
    proxy_request_buffering off. With nginx's default, a 256 MiB capture is
    written to nginx's temp directory in full and then written again to
    UPLOAD_DIR -- two copies on disk for one upload -- and the application's
    mid-stream size check cannot fire until nginx has accepted every byte.
    """
    assert ["off"] in values_of("proxy_request_buffering")


def test_proxy_passes_the_uri_unchanged():
    """
    `proxy_pass http://cryptomon_api;` with no URI part.

    Adding a trailing slash would make nginx strip the location prefix and
    hand the app its decoded, normalised idea of the path -- which breaks
    the ROOT_PATH arrangement documented in cryptomon.conf and silently
    changes what the report-id validation in fapi/app/uploads.py is shown.
    """
    passes = values_of("proxy_pass")
    assert passes, "no proxy_pass found"
    for args in passes:
        assert args == ["http://cryptomon_api"], (
            "proxy_pass must carry no URI part, got {0!r}".format(args))


def test_forwarded_headers_are_set():
    """
    Host and X-Forwarded-Proto are the two that build the post-upload
    redirect: starlette takes the netloc from the Host header in the scope
    and the scheme from scope["scheme"], which uvicorn sets from
    X-Forwarded-Proto. It does not read X-Forwarded-Host, so rewriting Host
    here would send the browser to the upstream's address.
    """
    set_headers = {args[0]: args[1:] for args in values_of("proxy_set_header")}
    assert set_headers.get("Host") == ["$host"]
    assert set_headers.get("X-Forwarded-Proto") == ["$scheme"]
    assert set_headers.get("X-Forwarded-For") == ["$proxy_add_x_forwarded_for"]


def test_the_upload_route_is_rate_limited():
    """One POST is one subprocess, and nothing else here costs one."""
    assert values_of("limit_req_zone"), "no rate limit zone defined"
    assert values_of("limit_req"), "the rate limit zone is never applied"
    assert values_of("limit_conn"), "no concurrency limit on uploads"


def test_tls_floor_and_no_session_tickets():
    protocols = values_of("ssl_protocols")
    assert protocols, "no ssl_protocols"
    offered = set(protocols[0])
    assert offered <= {"TLSv1.2", "TLSv1.3"}, offered
    assert "TLSv1.3" in offered
    # nginx generates one ticket key at start and never rotates it, so a
    # recovered key recovers every session since the last restart.
    assert ["off"] in values_of("ssl_session_tickets")


def test_ciphers_are_aead_and_forward_secret():
    ciphers = values_of("ssl_ciphers")
    assert ciphers, "no ssl_ciphers"
    for suite in ciphers[0][0].split(":"):
        assert suite.startswith("ECDHE-"), suite
        assert "GCM" in suite or "CHACHA20" in suite, suite
        assert "SHA1" not in suite and not suite.endswith("-SHA"), suite


def test_security_headers_present_and_no_dead_ones():
    added = {args[0] for args in values_of("add_header")}
    for header in ("Strict-Transport-Security", "X-Content-Type-Options",
                   "Content-Security-Policy", "Referrer-Policy"):
        assert header in added, "missing {0}".format(header)
    # Removed from every current browser, and while it existed its auditor
    # could itself be induced to leak. Setting it is worse than not.
    assert "X-XSS-Protection" not in added


def test_report_pages_are_not_cacheable():
    """A report holds SNI, which is browsing history."""
    text = nginx_text()
    cache_control = [args for args in values_of("add_header", text)
                     if args[0] == "Cache-Control"]
    assert cache_control, "no Cache-Control on the report routes"
    for args in cache_control:
        assert "no-store" in " ".join(args)


def test_nginx_prefix_matches_the_environment_file():
    """
    The one pair in this deployment that has to agree, checked.

    Everything else in deploy/ is independent. These two are the same value
    written in two files by two different people, and the failure when they
    drift is a 404 on every page.
    """
    conf = (NGINX_DIR / "cryptomon.conf").read_text(encoding="utf-8")
    locations = [args for name, args in directives(conf) if name == "location"]
    prefixes = {arg for args in locations for arg in args
                if arg.startswith("/") and arg != "/"}
    assert prefixes, "no prefixed location in cryptomon.conf"
    for found in prefixes:
        assert found.startswith(PREFIX), found

    env = (SYSTEMD_DIR / "api.env.example").read_text(encoding="utf-8")
    declared = re.search(r"^ROOT_PATH=(.*)$", env, re.M)
    assert declared, "api.env.example does not set ROOT_PATH"
    assert declared.group(1).strip() == PREFIX, (
        "api.env.example says ROOT_PATH={0!r} but the nginx locations are "
        "under {1!r}".format(declared.group(1).strip(), PREFIX))


# ==========================================================================
# the unit files
# ==========================================================================
UNIT_FILES = ("cryptomon-api.service", "cryptomon-sensor.service")


def unit_lines(name):
    """Directive lines only: `#` and `;` start a comment in a unit file."""
    text = (SYSTEMD_DIR / name).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith(("#", ";"))]


def unit_settings(name):
    found = {}
    for line in unit_lines(name):
        if "=" in line and not line.startswith("["):
            key, _, value = line.partition("=")
            found.setdefault(key.strip(), []).append(value.strip())
    return found


@pytest.mark.parametrize("name", UNIT_FILES)
def test_unit_files_exist_and_parse(name):
    lines = unit_lines(name)
    assert "[Unit]" in lines and "[Service]" in lines
    assert "[Install]" in lines


@pytest.mark.parametrize("name", UNIT_FILES)
def test_no_secret_in_a_unit_file(name):
    """
    The defect this replaces. The generated unit carried

        Environment="DB_URL=mongodb://cryptomonUser:<password>@..."

    in a file under /etc/systemd/system, which is 0644 by default, and in
    the output of `systemctl show` and `systemctl cat` -- both of which any
    user can run. Comments are stripped first, because the units explain
    what they replaced and the explanation contains the string.
    """
    body = "\n".join(unit_lines(name))
    lowered = body.lower()
    for marker in ("password", "passwd", "<password>", "secret=",
                   "api_key=", "token="):
        assert marker not in lowered, (
            "{0} has {1!r} in a live directive".format(name, marker))
    assert not re.search(r"mongodb(\+srv)?://[^\s:]+:[^\s@]+@", body), (
        "{0} carries a credentialled MongoDB URL".format(name))


@pytest.mark.parametrize("name", UNIT_FILES)
def test_environment_directive_is_not_used_for_configuration(name):
    """
    `Environment=` puts its value in the unit file. Everything configurable
    here travels through EnvironmentFile=, which systemd reads as PID 1
    before dropping to User= -- so the file can be 0600 root:root and the
    service account itself cannot open it.
    """
    settings_map = unit_settings(name)
    assert "EnvironmentFile" in settings_map, (
        "{0} must load its configuration from a file".format(name))
    assert "Environment" not in settings_map, (
        "{0} sets Environment= directly; use EnvironmentFile=".format(name))


def test_api_unit_has_no_privilege():
    """
    The half of the program that is reachable from the network is the half
    that should have nothing. It serves HTTP, reads MongoDB and forks a
    parser; it needs no capability at all, and in particular none of the
    eBPF and raw-socket privilege the sensor needs.
    """
    api = unit_settings("cryptomon-api.service")
    assert api.get("CapabilityBoundingSet") == [""]
    assert api.get("AmbientCapabilities") == [""]
    assert api.get("User") and api.get("User") != ["root"]

    families = api["RestrictAddressFamilies"][0].split()
    assert "AF_PACKET" not in families
    assert "AF_NETLINK" not in families


def test_api_unit_is_hardened():
    api = unit_settings("cryptomon-api.service")
    for directive, value in (("NoNewPrivileges", "yes"),
                             ("PrivateTmp", "yes"),
                             ("ProtectSystem", "strict"),
                             ("ProtectHome", "yes"),
                             ("ProtectKernelTunables", "yes"),
                             ("ProtectKernelModules", "yes"),
                             ("ProtectControlGroups", "yes"),
                             ("ProtectClock", "yes"),
                             ("RestrictSUIDSGID", "yes"),
                             ("RestrictNamespaces", "yes"),
                             ("LockPersonality", "yes"),
                             ("SystemCallArchitectures", "native")):
        assert api.get(directive) == [value], (
            "cryptomon-api.service: {0} should be {1}".format(directive,
                                                              value))
    # Reports are browsing history; the default 0022 would make them
    # world-readable.
    assert api.get("UMask") == ["0077"]


def test_api_unit_does_not_filter_the_sandbox_rlimits():
    """
    The hardening line that would silently break the upload sandbox.

    `SystemCallFilter=~@resources` is in most systemd hardening guides.
    setrlimit and prlimit64 are both in @resources, and
    pcapscan.sandbox.apply_limits() -- which the analysis worker calls on
    itself to bound RLIMIT_AS and RLIMIT_CPU -- swallows the resulting
    OSError and carries on:

        except (ValueError, OSError):
            continue

    So with @resources filtered the worker runs with no memory ceiling and
    no CPU ceiling, reports still come out correct, and the only symptom is
    that the protection the upload path is built on is gone.
    """
    api = unit_settings("cryptomon-api.service")
    for value in api.get("SystemCallFilter", []):
        assert "@resources" not in value, (
            "filtering @resources disables pcapscan.sandbox's own rlimits")
        assert "~" not in value or "setrlimit" not in value


def test_upload_dir_is_not_under_tmp():
    """
    PrivateTmp=yes puts /tmp in a namespace destroyed when the service
    stops. The UPLOAD_DIR default of /tmp/cryptomon-uploads would therefore
    lose every report on restart, while the upload form went on telling the
    user they were kept for REPORT_RETENTION_HOURS -- and `ls` from a shell
    would show an empty directory, which reads as a broken feature.
    """
    api = unit_settings("cryptomon-api.service")
    assert api.get("PrivateTmp") == ["yes"]

    env = (SYSTEMD_DIR / "api.env.example").read_text(encoding="utf-8")
    upload_dir = re.search(r"^UPLOAD_DIR=(.*)$", env, re.M)
    assert upload_dir, "api.env.example does not set UPLOAD_DIR"
    path = upload_dir.group(1).strip()
    assert not path.startswith("/tmp/"), (
        "UPLOAD_DIR under /tmp does not survive PrivateTmp=yes")
    assert not path.startswith("~"), (
        "uploads.py expanduser()s this, and ProtectHome=yes hides /home")

    # And systemd has to create it, or ProtectSystem=strict makes it EROFS.
    assert api.get("StateDirectory"), (
        "nothing creates UPLOAD_DIR's parent under ProtectSystem=strict")
    assert path.startswith("/var/lib/" + api["StateDirectory"][0])


def test_sensor_unit_keeps_the_privilege_it_needs():
    """
    The sensor is the one unit that genuinely needs kernel access. What is
    checked here is that it is bounded rather than simply root: an explicit
    CapabilityBoundingSet, and the two syscalls bcc cannot work without,
    which @system-service excludes because they are in @privileged.
    """
    sensor = unit_settings("cryptomon-sensor.service")
    caps = sensor["CapabilityBoundingSet"][0].split()
    for capability in ("CAP_BPF", "CAP_NET_ADMIN"):
        assert capability in caps, capability
    assert sensor.get("NoNewPrivileges") == ["yes"]
    # BPF maps are charged against RLIMIT_MEMLOCK before Linux 5.11, and the
    # 64 KiB default is not enough for a map of any size.
    assert sensor.get("LimitMEMLOCK") == ["infinity"]

    syscalls = " ".join(sensor.get("SystemCallFilter", []))
    assert "bpf" in syscalls.split(), (
        "bpf(2) is in @privileged, so @system-service alone forbids it")
    assert "perf_event_open" in syscalls.split()


def test_sensor_unit_does_not_lock_out_bcc():
    """
    Two directives that are right on the API unit and wrong here.

    ProtectKernelTunables remounts /sys/kernel/debug read-only, and bcc
    attaches probes by writing to /sys/kernel/debug/tracing -- so the
    sensor would start, stay running, and capture nothing. A monitoring
    tool silently monitoring nothing is the worst failure available.

    MemoryDenyWriteExecute would stop bcc compiling BPF C with LLVM in
    process, which is a JIT and needs writable-then-executable memory.
    """
    sensor = unit_settings("cryptomon-sensor.service")
    assert sensor.get("ProtectKernelTunables") in (None, ["no"])
    assert sensor.get("MemoryDenyWriteExecute") in (None, ["no"])


def test_sensor_unit_passes_an_interface():
    """
    cryptomon.py's parse_argz() prompts with input() when no -i is given.
    Under systemd there is no terminal, so that raises EOFError and the unit
    dies on every start, with a traceback that says nothing about a missing
    interface.
    """
    sensor = unit_settings("cryptomon-sensor.service")
    exec_start = sensor["ExecStart"][0]
    assert "cryptomon.py" in exec_start
    assert "-i " in exec_start, "the sensor must be told its interface"

    env = (SYSTEMD_DIR / "sensor.env.example").read_text(encoding="utf-8")
    assert re.search(r"^CRYPTOMON_IFACE=\S+", env, re.M), (
        "sensor.env.example must set CRYPTOMON_IFACE")


def test_units_are_separate_processes():
    """
    One unit ran both halves as root. The point of the split is that the
    process accepting uploads from the network and the process holding
    CAP_BPF are not the same process.
    """
    api = unit_settings("cryptomon-api.service")
    sensor = unit_settings("cryptomon-sensor.service")
    assert "api.py" in api["ExecStart"][0]
    assert "cryptomon.py" not in api["ExecStart"][0]
    assert "cryptomon.py" in sensor["ExecStart"][0]
    assert "api.py" not in sensor["ExecStart"][0]
    # And they do not share a credentials file: the sensor has no use for
    # API_KEY and should not be holding it.
    assert api["EnvironmentFile"] != sensor["EnvironmentFile"]


# ==========================================================================
# the installer
# ==========================================================================
def test_create_service_writes_no_unit_of_its_own():
    """
    The old script generated a unit with a `<password>` placeholder in an
    Environment= line and then ran `systemctl enable --now` on it, so the
    first thing every operator did was edit a root-owned unit by hand. The
    units are now files in deploy/systemd that can be read before they are
    installed.
    """
    script = (REPO / "create-service.sh").read_text(encoding="utf-8")

    # Comments and the closing here-document are both text, not commands.
    # The here-document is where the script tells the operator what to run
    # next, and `systemctl enable --now` is exactly what it should say
    # there -- so it has to be excluded before looking for the same string
    # as something the script would run itself.
    live = []
    heredoc = None
    for line in script.splitlines():
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        opened = re.search(r"<<-?'?([A-Za-z_][A-Za-z0-9_]*)'?\s*$", line)
        if opened:
            heredoc = opened.group(1)
            continue
        if not line.lstrip().startswith("#"):
            live.append(line)
    live = "\n".join(live)

    assert "<password>" not in live
    assert not re.search(r"^\s*Environment=", live, re.M), (
        "create-service.sh writes an Environment= line again")
    # It must not START a service whose credentials are still placeholders.
    # A unit that fails on every boot because nobody filled in DB_URL is a
    # unit everybody learns to ignore.
    assert not re.search(r"systemctl\s+(enable\s+--now|start)\s+cryptomon",
                         live), (
        "create-service.sh should not start a service before its "
        "EnvironmentFile has been filled in")
    # It should still reload, so that an install followed by a manual start
    # does not need a second command nobody documented.
    assert "systemctl daemon-reload" in live


def test_example_env_files_hold_no_real_secret():
    for name in ("api.env.example", "sensor.env.example"):
        text = (SYSTEMD_DIR / name).read_text(encoding="utf-8")
        live = "\n".join(line for line in text.splitlines()
                         if not line.lstrip().startswith("#"))
        credentialled = re.findall(r"mongodb(?:\+srv)?://[^\s:]+:([^\s@]+)@",
                                   live)
        for password in credentialled:
            assert password == "CHANGE-ME", (
                "{0} has something other than a placeholder: {1!r}"
                .format(name, password))
        assert re.search(r"^API_KEY=\s*$", live, re.M) or \
            "API_KEY" not in live, "API_KEY must ship empty"


def test_no_real_environment_file_is_committed():
    """A filled-in api.env belongs in /etc/cryptomon, mode 0600, not here."""
    for leaked in ("api.env", "sensor.env"):
        assert not (SYSTEMD_DIR / leaked).exists(), (
            "deploy/systemd/{0} looks like a real credentials file"
            .format(leaked))
