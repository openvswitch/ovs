#!/bin/bash
set -ev
pip install --user six

brew uninstall libtool && brew install libtool || true
