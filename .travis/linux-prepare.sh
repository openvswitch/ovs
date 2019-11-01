#!/bin/bash

set -ev

# Build and install sparse.
#
# Explicitly disable sparse support for llvm because some travis
# environments claim to have LLVM (llvm-config exists and works) but
# linking against it fails.
git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git
cd sparse
make -j4 HAVE_LLVM= install
cd ..

pip install --disable-pip-version-check --user six flake8 hacking
pip install --user --upgrade docutils

if [ "$M32" ]; then
    # 32-bit and 64-bit libunwind can not be installed at the same time.
    # This will remove the 64-bit libunwind and install 32-bit version.
    sudo apt-get install -y libunwind-dev:i386
fi

# IPv6 is supported by kernel but disabled in TravisCI images:
#   https://github.com/travis-ci/travis-ci/issues/8891
# Enable it to avoid skipping of IPv6 related tests.
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
