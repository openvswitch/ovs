#!/bin/bash
set -ev
pip2 install --user six
pip2 install --user --upgrade docutils

brew update || true
brew uninstall libtool && brew install libtool || true
