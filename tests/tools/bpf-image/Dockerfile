# Environment for the eBPF checks.
#
# Pinned deliberately. bcc parses the kernel headers it compiles against, and
# Ubuntu's python3-bpfcc is older than the kernel a CI runner happens to boot
# -- against 6.17 headers it fails inside include/linux/bpf.h itself, on
# struct bpf_wq and BPF_LOAD_ACQ, before it ever reaches our program. Fixing
# the environment is the point of this file: the C is then the only variable.
#
#   docker build -t cryptomon-bpf tests/tools/bpf-image
#   docker run --rm --privileged -v "$PWD":/work -w /work cryptomon-bpf \
#       python3 tests/tools/check_bpf.py
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# linux-headers-generic, not linux-headers-$(uname -r): the container must
# compile against headers this bcc understands, not the host's kernel.
RUN apt-get update -qq && \
    apt-get install -y -qq python3-bpfcc linux-headers-generic && \
    rm -rf /var/lib/apt/lists/*
