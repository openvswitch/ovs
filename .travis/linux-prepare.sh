#!/bin/bash

# Logging to syslog could be way too slow on Travis.
# Stopping the rsyslog daemon to allow tests to fit the time limit.
sudo service rsyslog stop

# Build and install sparse.
#
# Explicitly disable sparse support for llvm because some travis
# environments claim to have LLVM (llvm-config exists and works) but
# linking against it fails.
git clone git://git.kernel.org/pub/scm/devel/sparse/chrisl/sparse.git
cd sparse && make HAVE_LLVM= install && cd ..

# Incompatibility between flake8 3.0.x and the hacking plugin:
# https://gitlab.com/pycqa/flake8/issues/153
# https://bugs.launchpad.net/hacking/+bug/1607942
pip install --disable-pip-version-check --user six "flake8<3.0" hacking
