#!/bin/bash
set -ev
pip install --user six
pip install --user --upgrade docutils

brew update || true
brew uninstall libtool && brew install libtool || true
