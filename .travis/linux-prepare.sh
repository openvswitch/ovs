#!/bin/bash

set -ev

# Build and install sparse.
#
# Explicitly disable sparse support for llvm because some travis
# environments claim to have LLVM (llvm-config exists and works) but
# linking against it fails.
git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git
cd sparse
# Commit bb1bf748580d ("cgcc: gendeps for -MM, -MD & -MMD too") makes
# sparse ignore almost all source files, because 'make' uses '-MD' to
# generate dependencies as a side effect within compilation commands.
git revert bb1bf748580d --no-commit
git diff HEAD
make -j4 HAVE_LLVM= install
cd ..

pip install --disable-pip-version-check --user six flake8 hacking
pip install --user --upgrade docutils
