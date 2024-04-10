#!/bin/bash

set -ev

# Installing wheel separately because it may be needed to build some
# of the packages during dependency backtracking and pip >= 22.0 will
# abort backtracking on build failures:
#     https://github.com/pypa/pip/issues/10655
pip3 install --disable-pip-version-check --user wheel
pip3 install --disable-pip-version-check --user pyelftools
pip3 install --user  'meson>=1.4,<1.5'
