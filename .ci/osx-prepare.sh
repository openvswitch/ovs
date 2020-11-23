#!/bin/bash
set -ev
pip install --user six

brew update || true
brew uninstall libtool && brew install libtool || true
