#!/bin/bash
set -ev

# clone and build pthreads4w
git clone https://git.code.sf.net/p/pthreads4w/code pthreads4w-code
cd pthreads4w-code
nmake all install
cd ..
rm -rf pthreads4w-code