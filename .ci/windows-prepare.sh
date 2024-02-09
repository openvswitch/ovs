#!/bin/bash
set -ex

mkdir -p /var/cache/pacman/pkg/
pacman -S --noconfirm --needed automake autoconf libtool make patch

# Use an MSVC linker and a Windows version of Python.
mv $(which link) $(which link)_copy
mv $(which python3) $(which python3)_copy

cd /c/pthreads4w-code && nmake all install
