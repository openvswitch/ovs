#!/bin/bash

set -ev

if [ "$DEB_PACKAGE" ]; then
    # We're not using sparse for debian packages, tests are skipped and
    # all extra dependencies tracked by mk-build-deps.
    exit 0
fi

# Build and install sparse.
#
# Explicitly disable sparse support for llvm because some travis
# environments claim to have LLVM (llvm-config exists and works) but
# linking against it fails.
# Disabling sqlite support because sindex build fails and we don't
# really need this utility being installed.
git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git
cd sparse
make -j4 HAVE_LLVM= HAVE_SQLITE= install
cd ..

pip3 install --disable-pip-version-check --user \
    flake8 hacking sphinx pyOpenSSL wheel setuptools
pip3 install --user --upgrade docutils
pip3 install --user  'meson==0.47.1'

if [ "$M32" ]; then
    # Installing 32-bit libraries.
    pkgs="gcc-multilib"
    if [ -z "$GITHUB_WORKFLOW" ]; then
        # 32-bit and 64-bit libunwind can not be installed at the same time.
        # This will remove the 64-bit libunwind and install 32-bit version.
        # GitHub Actions doesn't have 32-bit versions of these libs.
        pkgs=$pkgs" libunwind-dev:i386 libunbound-dev:i386"
    fi

    sudo apt-get install -y $pkgs
fi

# IPv6 is supported by kernel but disabled in TravisCI images:
#   https://github.com/travis-ci/travis-ci/issues/8891
# Enable it to avoid skipping of IPv6 related tests.
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
