#! /bin/sh
autoreconf --install --force

# Ensure that debian/changelog is up-to-date.
VERSION=`autom4te --language=autoconf -t 'AC_INIT:$2' configure.ac`
build-aux/update-debian-changelog debian/changelog "$VERSION"
