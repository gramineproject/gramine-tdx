FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y ca-certificates

# Intel's RSA-2048 key signing the intel-sgx/sgx_repo repository. Expires 2027-03-20.
# https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
# TODO after Intel releases for noble: fix mantic to noble
COPY .ci/intel-sgx-deb.key /etc/apt/keyrings/intel-sgx-deb.asc
RUN echo deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu mantic main > /etc/apt/sources.list.d/intel-sgx.list

# Dependencies for actual build.
# NOTE: COPY invalidates docker cache when source file changes,
# so `apt-get build-dep` will rerun if dependencies change, despite no change
# in dockerfile.
RUN mkdir /debian
COPY debian/control /debian
RUN apt-get update && apt-get -y build-dep --no-install-recommends --no-install-suggests /
RUN rm -rf /debian

# runtime dependencies of Gramine, for running tests
# keep this synced with debian/control
RUN apt-get update && apt-get satisfy -y \
    'libcurl4 (>= 7.58)' \
    'libprotobuf-c1' \
    'python3' \
    'python3 (>= 3.10) | python3-pkg-resources' \
    'python3-click (>= 6.7)' \
    'python3-cryptography' \
    'python3-jinja2' \
    'python3-pyelftools' \
    'python3-tomli (>= 1.1.0)' \
    'python3-tomli-w (>= 0.4.0)' \
    'python3-voluptuous'

# dependencies for various tests, CI-Examples, etc.
# clang: asan and ubsan builds
# cpio dwarves kmod qemu-kvm: for building kernel modules and running VMs
# gdb: tested in libos suite
# git: scripts/gitignore-test (among others)
# jq: used in jenkinsfiles
# libomp-dev: needed for libos/test/regression/openmp.c
# libunwind8: libos/test/regression/bootstrap_cpp.manifest.template
# musl-tools: for compilation with musl (not done in deb/rpm)
# ncat: used in scripts/wait_for_server
# python3-pytest-xdist: for pytest -n option, to run in parallel
# python3-pytest: for running tests
# shellcheck: .ci/run-shellcheck
# wget: scripts/download
RUN apt-get update && apt-get install -y \
    clang \
    cmake \
    cpio \
    dwarves \
    gdb \
    git \
    jq \
    kmod \
    libomp-dev \
    libunwind8 \
    musl-tools \
    ncat \
    python3-pytest \
    python3-pytest-xdist \
    qemu-kvm \
    shellcheck \
    wget

# dependencies for Gramine-TDX dependencies (TD-Shim, socat, virtio, etc)
RUN apt-get update && apt-get install -y \
    curl \
    gawk \
    libcap-ng-dev \
    libseccomp-dev \
    llvm \
    nasm \
    python3-psutil \
    software-properties-common

# TDX software stack
RUN add-apt-repository -y ppa:kobuk-team/tdx-release && \
    apt-get update && \
    apt-get install -y --allow-downgrades \
    qemu-system-x86 \
    libvirt-clients \
    ovmf

RUN ln -sf /usr/bin/qemu-system-x86_64 /usr/local/bin/qemu

CMD ["bash"]
