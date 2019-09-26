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
