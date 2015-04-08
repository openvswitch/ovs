#!/bin/bash

sudo -E apt-get update -qq
sudo -E apt-get install -qq libssl-dev llvm-dev
sudo -E apt-get install -qq gcc-multilib
if [ "$DPDK" ]; then
    sudo -E apt-get install -qq libfuse-dev
fi

git clone git://git.kernel.org/pub/scm/devel/sparse/chrisl/sparse.git
cd sparse && make && sudo -E make install PREFIX=/usr && cd ..
