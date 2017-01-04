#!/bin/bash

git clone git://git.kernel.org/pub/scm/devel/sparse/chrisl/sparse.git
cd sparse && make && make install && cd ..

pip install --disable-pip-version-check --user six flake8 hacking
