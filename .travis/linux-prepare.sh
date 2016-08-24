#!/bin/bash

git clone git://git.kernel.org/pub/scm/devel/sparse/chrisl/sparse.git
cd sparse && make && make install && cd ..

# Incompatibility between flake8 3.0.x and the hacking plugin:
# https://gitlab.com/pycqa/flake8/issues/153
# https://bugs.launchpad.net/hacking/+bug/1607942
pip install --disable-pip-version-check --user six "flake8<3.0" hacking
