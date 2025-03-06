#!/bin/bash

set -ev

if [ "$DEB_PACKAGE" ]; then
    # We're not using sparse for debian packages, tests are skipped and
    # all extra dependencies tracked by mk-build-deps.
    exit 0
fi

# Build and install sparse.
#
# Disabling sqlite support because sindex build fails and we don't
# really need this utility being installed.
if test -d sparse; then
    pushd sparse
    make -j4 HAVE_SQLITE= install
    popd
fi

# Installing wheel separately because it may be needed to build some
# of the packages during dependency backtracking and pip >= 22.0 will
# abort backtracking on build failures:
#     https://github.com/pypa/pip/issues/10655
pip3 install --disable-pip-version-check --user wheel
pip3 install --disable-pip-version-check --user \
    flake8 netaddr pyparsing sarif-tools==2.0.0 sphinx setuptools

# Install python test dependencies
pip3 install -r python/test_requirements.txt

# Make sure IPv6 is enabled to avoid skipping of IPv6 related tests.
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
