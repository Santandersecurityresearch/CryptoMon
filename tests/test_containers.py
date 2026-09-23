"""
The container images, checked without a container runtime.

Everything in docker/ is a promise made to a machine that is not this one,
and most of the ways it can be broken are visible in the text: a base image
that floats, a credential that ends up in a layer, a `USER` line deleted
during a debugging session and not put back, a `.dockerignore` that stops
excluding the 254MB of packet captures somebody left in the working tree.
None of that needs a daemon to catch, and CI has no daemon to offer -- the
merge gate runs on a runner with no docker socket guaranteed.

So the checks below read the files. `docker build` is exercised by one
test at the bottom, which skips itself when there is no daemon and is
deliberately not in the smoke set: it costs seconds, and the smoke set is
the merge gate.

The Dockerfile reader here is not a Dockerfile parser in any general sense.
It joins continuations, drops comments and yields (instruction, argument)
pairs, which is all these assertions need and all that can be checked
without reimplementing BuildKit.
"""
import fnmatch
import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKER = ROOT / "docker"
DOCKERIGNORE = ROOT / ".dockerignore"

DOCKERFILES = {
    "api": DOCKER / "Dockerfile.api",
    "offline": DOCKER / "Dockerfile.offline",
    "sensor": DOCKER / "Dockerfile.sensor",
}

# The images that serve or read somebody else's data and have no reason to
# be root. The sensor is not here and that is deliberate: docker puts
# --cap-add capabilities in the *permitted* set of the initial process and a
# non-root uid inherits none of them across execve, so a `USER` line there
# would produce a container that looks safer and cannot load its program.
UNPRIVILEGED = ("api", "offline")

# Everything the images are built from. `latest` is not a version, it is a
# promise that the build will change under you.
FORBIDDEN_TAGS = ("latest", "")

INSTRUCTIONS = {
    "FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY",
    "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD",
    "STOPSIGNAL", "HEALTHCHECK", "SHELL", "MAINTAINER",
}

# Marked per test rather than per module. Everything here but the last test
# is text, and belongs in the merge gate; the last test wants a daemon and
# does not.
smoke = pytest.mark.smoke


# --------------------------------------------------------------------------
# reading a Dockerfile
# --------------------------------------------------------------------------
def read_instructions(path):
    """
    (INSTRUCTION, argument) for each instruction, continuations joined.

    Comment lines are dropped *after* continuations are joined would be
    wrong -- a `#` line inside a continuation is a comment in docker too --
    so they are dropped as they are read, which is what BuildKit does.
    """
    parsed = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not pending and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if pending and line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        statement = (pending + line).strip()
        pending = ""
        if not statement:
            continue
        head, _, rest = statement.partition(" ")
        parsed.append((head.upper(), rest.strip()))
    if pending.strip():
        parsed.append(tuple(pending.strip().split(" ", 1)))
    return parsed


def image_references(path):
    """Every base image named by a FROM, with the stage alias dropped."""
    references = []
    for instruction, argument in read_instructions(path):
        if instruction != "FROM":
            continue
        words = argument.split()
        reference = words[0]
        if reference.startswith("--platform="):        # would pin the arch
            reference = words[1]
        references.append(reference)
    return references


# --------------------------------------------------------------------------
# every file is there and parses
# --------------------------------------------------------------------------
@smoke
@pytest.mark.parametrize("name", sorted(DOCKERFILES))
def test_dockerfile_exists_and_parses(name):
    path = DOCKERFILES[name]
    assert path.is_file(), "{0} is missing".format(path)
    parsed = read_instructions(path)
    assert parsed, "{0} has no instructions".format(path)
    unknown = sorted({head for head, _ in parsed} - INSTRUCTIONS)
    assert not unknown, "{0}: not Dockerfile instructions: {1}".format(
        path.name, unknown)
    # ARG may precede FROM -- that is how a build argument reaches the base
    # image reference -- and nothing else may.
    heads = [head for head, _ in parsed]
    assert heads[heads.index("FROM") - 1:heads.index("FROM")] in ([], ["ARG"]), \
        "{0}: something other than ARG precedes the first FROM".format(path.name)
    assert "FROM" in heads, "{0}: no FROM".format(path.name)


@smoke
def test_dockerignore_exists():
    assert DOCKERIGNORE.is_file(), \
        ".dockerignore is missing from the repository root, which is the " \
        "context every image in docker/ builds from"


@smoke
def test_compose_exists_and_is_yaml():
    compose = DOCKER / "compose.yaml"
    assert compose.is_file()
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(compose.read_text(encoding="utf-8"))
    assert set(document["services"]) == {"mongo", "api", "sensor"}


# --------------------------------------------------------------------------
# base images do not float
# --------------------------------------------------------------------------
@smoke
@pytest.mark.parametrize("name", sorted(DOCKERFILES))
def test_base_images_are_pinned(name):
    """
    A digest, or at the very least a tag that is not `latest`.

    An unpinned base is a build whose output changes without the repository
    changing, which makes every other assertion in this file a statement
    about a moment rather than about the image.
    """
    references = image_references(DOCKERFILES[name])
    assert references, "{0}: no FROM".format(name)
    for reference in references:
        if "@sha256:" in reference:
            digest = reference.split("@sha256:", 1)[1]
            assert re.fullmatch(r"[0-9a-f]{64}", digest), \
                "{0}: {1} is not a sha256 digest".format(name, reference)
            continue
        assert ":" in reference, \
            "{0}: {1} has no tag, which means :latest".format(name, reference)
        tag = reference.rsplit(":", 1)[1]
        assert tag not in FORBIDDEN_TAGS, \
            "{0}: {1} floats".format(name, reference)


@smoke
def test_multi_stage_files_use_one_base_digest():
    """
    Both stages of a two-stage file are the same image.

    A build stage that has drifted from its runtime stage produces wheels
    linked against one libc and a runtime holding another, and the failure
    arrives months later as a missing shared object.
    """
    for name in ("api", "offline"):
        references = image_references(DOCKERFILES[name])
        assert len(set(references)) == 1, \
            "{0}: build and runtime stages differ: {1}".format(
                name, sorted(set(references)))


@smoke
def test_compose_images_are_pinned():
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(
        (DOCKER / "compose.yaml").read_text(encoding="utf-8"))
    for name, service in document["services"].items():
        reference = service.get("image", "")
        if "build" in service:
            # Built here, so the pin that matters is the Dockerfile's and is
            # checked above. `image:` is only the local tag.
            continue
        assert "@sha256:" in reference or (
            ":" in reference
            and reference.rsplit(":", 1)[1] not in FORBIDDEN_TAGS), \
            "compose service {0}: {1} floats".format(name, reference)


# --------------------------------------------------------------------------
# nothing runs as root that does not have to
# --------------------------------------------------------------------------
@smoke
@pytest.mark.parametrize("name", UNPRIVILEGED)
def test_user_is_not_root(name):
    users = [argument for head, argument in read_instructions(DOCKERFILES[name])
             if head == "USER"]
    assert users, "{0}: no USER instruction, so it runs as root".format(name)
    final = users[-1]
    assert final not in ("root", "0", "root:root", "0:0"), \
        "{0}: USER {1}".format(name, final)
    # A name the host cannot resolve is not much use for a bind mount, so
    # these images use a numeric id. Accept either, but insist the uid part
    # is not zero.
    uid = final.split(":", 1)[0]
    if uid.isdigit():
        assert int(uid) != 0, "{0}: USER {1} is root by number".format(
            name, final)


@smoke
def test_sensor_documents_why_it_is_root():
    """
    The sensor is the exception, and an exception nobody explained is an
    exception somebody will copy.
    """
    text = DOCKERFILES["sensor"].read_text(encoding="utf-8").lower()
    assert "ambient" in text and "permitted set" in text, \
        "Dockerfile.sensor runs as root and must say why -- docker does not " \
        "give a non-root uid the capabilities added with --cap-add"


@smoke
def test_no_dockerfile_installs_a_build_toolchain_in_its_final_stage():
    """
    A compiler in a served image is a compiler an attacker did not have to
    bring. The api and offline images install wheels in a stage that is
    thrown away; the sensor installs none at all (bcc compiles with its own
    bundled libclang, which is not the same thing as a toolchain being
    available to a shell).
    """
    toolchain = ("build-essential", "gcc ", "g++", "clang ", "make ")
    for name, path in DOCKERFILES.items():
        final = True
        for head, argument in read_instructions(path):
            if head == "FROM":
                # A stage with no `AS <name>` is one nothing can copy from,
                # which in these files means it is the one that ships.
                final = "AS " not in argument.upper()
            if head == "RUN" and final:
                for package in toolchain:
                    assert package not in argument + " ", \
                        "{0}: final stage installs {1}".format(name, package)


# --------------------------------------------------------------------------
# no credential reaches a layer
# --------------------------------------------------------------------------
# What a value is allowed to be: empty, a compose interpolation, or a string
# that announces itself as a placeholder.
PLACEHOLDER = re.compile(r"change[-_]me|placeholder|<[a-z_]+>", re.I)
CREDENTIAL = re.compile(
    r"""(?ix)
    \b(pass(word|wd)?|secret|api[_-]?key|token|credential)s?\b
    \s* [:=] \s*
    (?P<value>\S+)
    """)

SCANNED = ("Dockerfile.api", "Dockerfile.offline", "Dockerfile.sensor",
           "compose.yaml", "env.example", "sensor-entrypoint.sh")


@smoke
@pytest.mark.parametrize("filename", SCANNED)
def test_no_secret_is_baked_in(filename):
    path = DOCKER / filename
    if not path.is_file():
        pytest.skip("{0} is not part of this change".format(filename))
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(),
                                  start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = CREDENTIAL.search(line)
        if not match:
            continue
        value = match.group("value").strip("'\"},")
        assert (not value
                or value.startswith("${")
                or "${" in value
                or PLACEHOLDER.search(value)), \
            "{0}:{1} looks like a real credential: {2}".format(
                filename, number, stripped)


@smoke
def test_the_compose_password_announces_itself():
    """
    There is a default MongoDB password in compose.yaml, because a database
    with no credential is one edited `ports:` line away from being an open
    one. It must be impossible to mistake for a generated secret.
    """
    text = (DOCKER / "compose.yaml").read_text(encoding="utf-8")
    assert "change-me-this-is-not-a-password" in text
    readme = (DOCKER / "README.md").read_text(encoding="utf-8")
    # On the first screen, not in an appendix.
    head = "\n".join(readme.splitlines()[:40])
    assert "change-me-this-is-not-a-password" in head, \
        "docker/README.md must say on its first screen that the shipped " \
        "password is a placeholder"


@smoke
def test_no_dockerfile_copies_an_env_file():
    for name, path in DOCKERFILES.items():
        for head, argument in read_instructions(path):
            if head in ("COPY", "ADD"):
                assert ".env" not in argument, \
                    "{0}: {1} {2}".format(name, head, argument)


# --------------------------------------------------------------------------
# the build context
# --------------------------------------------------------------------------
def ignore_patterns():
    lines = []
    for raw in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _segments(text):
    return [part for part in text.strip("/").split("/")
            if part not in ("", ".")]


def _match(segments, pattern_segments):
    """Go's filepath.Match, per segment, with `**` absorbing any number."""
    if not pattern_segments:
        return not segments
    if pattern_segments[0] == "**":
        return any(_match(segments[index:], pattern_segments[1:])
                   for index in range(len(segments) + 1))
    if not segments:
        return False
    if not fnmatch.fnmatchcase(segments[0], pattern_segments[0]):
        return False
    return _match(segments[1:], pattern_segments[1:])


def is_excluded(path, patterns=None):
    """
    Would docker drop this path from the context?

    A pattern that matches a directory excludes everything beneath it, which
    is why each prefix of the path is tried. The last matching rule wins, so
    that a later `!` re-includes.
    """
    patterns = ignore_patterns() if patterns is None else patterns
    segments = _segments(path)
    decision = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        pattern_segments = _segments(pattern[1:] if negated else pattern)
        hit = any(_match(segments[:index], pattern_segments)
                  for index in range(1, len(segments) + 1))
        if hit:
            decision = not negated
    return decision


@smoke
@pytest.mark.parametrize("path", [
    # The corpora. 254MB of captures and a 690MB monitor dump.
    "CryptomonData",
    "CryptomonData/UC_1-Common_Apps-Mac_PCAPs/something.pcap",
    "CryptomonData/C_1-Common_Apps-Windows_11_PCAPs.zip",
    "sandbox",
    "sandbox/monitor-NUC-dump1.json",
    "sandbox/A007653A_00001_20230626092541.pcap",
    # 570MB of history, and a place credentials live.
    ".git",
    ".git/config",
    # Bytecode compiled by whatever interpreter the developer happened to
    # run, which is rarely the one in the image.
    "__pycache__/api.cpython-311.pyc",
    "pcapscan/__pycache__/reader.cpython-312.pyc",
    "cryptomon/parsers/__pycache__/tls.cpython-310.pyc",
    # Captures anywhere, including the committed fixtures: no image reads a
    # capture from inside itself.
    "tests/fixtures/chrome_mac.pcap",
    "tests/fixtures/streams/tls12_certificate.pcap",
    "a-capture-somebody-dropped-here.pcapng",
    # Credentials.
    ".env",
    "docker/.env",
    "cryptomon.service",
])
def test_dockerignore_excludes(path):
    assert is_excluded(path), \
        ".dockerignore lets {0} into every build context".format(path)


@smoke
@pytest.mark.parametrize("path", [
    "requirements.txt",
    "api.py",
    "cryptomon.py",
    "pcapscan/cli.py",
    "cryptomon/bpf.py",
    "cryptomon/tls_ciphersuites.csv",
    "fapi/config/__init__.py",
    "fapi/app/templates/upload.html",
    "tests/tools/check_bpf.py",
    "docker/sensor-entrypoint.sh",
    "docker/env.example",
])
def test_dockerignore_keeps_what_the_images_copy(path):
    assert not is_excluded(path), \
        ".dockerignore excludes {0}, which an image COPYs".format(path)


@smoke
def test_every_copy_source_exists_and_survives_dockerignore():
    """
    A COPY of something .dockerignore excludes fails the build, and a COPY
    of something that does not exist fails it too -- both at the end of a
    build rather than here.
    """
    for name, path in DOCKERFILES.items():
        for head, argument in read_instructions(path):
            if head not in ("COPY", "ADD"):
                continue
            words = argument.split()
            if any(word.startswith("--from=") for word in words):
                continue          # comes from an earlier stage, not the context
            sources = [word for word in words[:-1]
                       if not word.startswith("--")]
            for source in sources:
                assert (ROOT / source).exists(), \
                    "{0}: COPY {1} -- no such path".format(name, source)
                assert not is_excluded(source), \
                    "{0}: COPY {1} -- excluded by .dockerignore".format(
                        name, source)


# --------------------------------------------------------------------------
# signals, health, and the shape of the runtime
# --------------------------------------------------------------------------
@smoke
@pytest.mark.parametrize("name", sorted(DOCKERFILES))
def test_entrypoint_and_cmd_are_exec_form(name):
    """
    JSON array form, so pid 1 is the process rather than a shell that will
    not forward SIGTERM to it. `docker stop` on a shell-form CMD waits the
    full ten seconds and then kills.
    """
    for head, argument in read_instructions(DOCKERFILES[name]):
        if head not in ("ENTRYPOINT", "CMD"):
            continue
        assert argument.startswith("["), \
            "{0}: {1} {2} is shell form".format(name, head, argument)
        json.loads(argument)


@smoke
def test_api_has_a_healthcheck():
    heads = [head for head, _ in read_instructions(DOCKERFILES["api"])]
    assert "HEALTHCHECK" in heads


@smoke
def test_api_declares_the_upload_directory_as_a_volume():
    """
    UPLOAD_DIR defaults to /tmp/cryptomon-uploads, which in a container is a
    directory in the writable layer that grows with every capture analysed
    and is lost when the container is replaced -- taking every report link
    anybody has shared with it.
    """
    instructions = read_instructions(DOCKERFILES["api"])
    upload_dir = None
    for head, argument in instructions:
        if head == "ENV" and argument.startswith("UPLOAD_DIR="):
            upload_dir = argument.split("=", 1)[1].strip().strip('"')
    assert upload_dir, "Dockerfile.api does not set UPLOAD_DIR"
    volumes = [argument for head, argument in instructions if head == "VOLUME"]
    assert any(upload_dir in volume for volume in volumes), \
        "UPLOAD_DIR={0} is not a declared volume: {1}".format(
            upload_dir, volumes)


@smoke
def test_api_binds_all_interfaces_inside_the_container_only():
    """
    HOST=0.0.0.0 in the image, 127.0.0.1 in the compose `ports:` line.

    fapi.config defaults HOST to 127.0.0.1 because on a host that means "not
    reachable". Inside a container it means "not reachable even by
    `docker run -p`", so the bind address moves out and the boundary moves
    to the network namespace. That is only true while the published port is
    bound to loopback, which is what the second half of this asserts.
    """
    text = DOCKERFILES["api"].read_text(encoding="utf-8")
    assert re.search(r"^ENV HOST=0\.0\.0\.0", text, re.M), \
        "Dockerfile.api must set HOST explicitly; the 127.0.0.1 default is " \
        "unreachable in a container"
    assert "PR-10" in text, \
        "the flip from the 127.0.0.1 default needs the reason beside it"

    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(
        (DOCKER / "compose.yaml").read_text(encoding="utf-8"))
    for name in ("api", "mongo"):
        for published in document["services"][name].get("ports", []):
            assert str(published).startswith("${") or \
                str(published).startswith("127.0.0.1:"), \
                "compose publishes {0} on {1} rather than loopback".format(
                    name, published)
            if str(published).startswith("${"):
                assert ":-127.0.0.1}" in str(published), \
                    "compose service {0}: the default bind address for " \
                    "{1} is not loopback".format(name, published)


@smoke
def test_compose_keeps_the_sensor_behind_a_profile():
    """
    Host networking and elevated capabilities must not be what `docker
    compose up` does by default. Evaluating this project means analysing a
    capture, which needs neither.
    """
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(
        (DOCKER / "compose.yaml").read_text(encoding="utf-8"))
    sensor = document["services"]["sensor"]
    assert sensor.get("profiles"), "the sensor is in the default set"
    assert not sensor.get("privileged"), \
        "--privileged grants every capability and the host's devices; the " \
        "sensor needs four capabilities"
    assert set(sensor.get("cap_add", [])) >= {"BPF", "PERFMON"}
    for name in ("api", "mongo"):
        assert not document["services"][name].get("privileged")
        assert not document["services"][name].get("cap_add")


@smoke
def test_compose_api_is_read_only_with_a_writable_volume():
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load(
        (DOCKER / "compose.yaml").read_text(encoding="utf-8"))
    api = document["services"]["api"]
    assert api.get("read_only") is True
    assert api.get("cap_drop") == ["ALL"]
    assert any("/var/lib/cryptomon/uploads" in str(volume)
               for volume in api.get("volumes", []))


@smoke
def test_sensor_entrypoint_is_executable_and_execs():
    """
    It runs as pid 1. If it ends in a call rather than an exec, `docker
    stop` reaches the wrapper and the monitor never hears about it.
    """
    entrypoint = DOCKER / "sensor-entrypoint.sh"
    assert entrypoint.is_file()
    assert os.access(entrypoint, os.X_OK), \
        "{0} is not executable; the COPY preserves the mode".format(
            entrypoint.name)
    text = entrypoint.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert "exec python3" in text


@smoke
def test_sensor_installs_headers_generic_not_the_running_kernel():
    """
    linux-headers-generic, never linux-headers-$(uname -r).

    bcc parses the headers it compiles against, and in a container
    `uname -r` is the *host's* kernel: the headers for it are not installed,
    and if they were, Ubuntu's python3-bpfcc could not parse them -- it dies
    inside include/linux/bpf.h on struct bpf_wq. This is the single lesson
    tests/tools/bpf-image/Dockerfile exists to record.
    """
    instructions = read_instructions(DOCKERFILES["sensor"])
    installs = [argument for head, argument in instructions if head == "RUN"]
    assert any("linux-headers-generic" in argument for argument in installs)
    for argument in installs:
        assert "uname" not in argument, \
            "Dockerfile.sensor resolves a package name from the running " \
            "kernel: {0}".format(argument[:120])


# --------------------------------------------------------------------------
# the one test that wants a daemon
# --------------------------------------------------------------------------
def docker_available():
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.mark.skipif(not docker_available(), reason="no docker daemon")
def test_offline_image_builds_and_analyses_a_capture(tmp_path):
    """
    The claim the offline image makes, end to end: build it, give it a
    capture on a read-only mount with no network and no writable root, and
    get the certificate inventory back.

    Not marked smoke. It needs a daemon, which CI does not guarantee, and it
    costs seconds even with a warm cache.

    Tagged `:pytest` and untagged again on the way out, whatever happened.
    A test suite that leaves a 164MB image behind every time it runs is a
    test suite somebody stops running on their laptop -- and this one was
    written on a machine whose disk was full.
    """
    capture = ROOT / "tests" / "fixtures" / "streams" / "tls12_certificate.pcap"
    assert capture.is_file()
    tag = "cryptomon-offline:pytest"

    try:
        build = subprocess.run(
            ["docker", "build", "-q", "-f", "docker/Dockerfile.offline",
             "-t", tag, "."],
            cwd=str(ROOT), capture_output=True, text=True, timeout=900)
        assert build.returncode == 0, build.stderr[-4000:]

        run = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--read-only",
             "-v", "{0}:/captures:ro".format(capture.parent),
             tag, "/captures/" + capture.name],
            capture_output=True, text=True, timeout=300)
        assert run.returncode == 0, run.stderr[-4000:]
        # The certificate section is the part that needs the one
        # third-party package in the image, so it is the part worth
        # asserting.
        assert "Certificate keys" in run.stdout
        assert "RSA-2048" in run.stdout
        assert "TLSv1.2" in run.stdout
    finally:
        # Untags rather than deletes: the layers stay in the build cache, so
        # an image the operator built themselves is untouched and the next
        # run of this test is still fast.
        subprocess.run(["docker", "rmi", tag], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=120)
