#!/bin/bash

sudo apt-get update -qq
sudo apt-get install -qq libssl-dev llvm-dev

wget https://www.kernel.org/pub/software/devel/sparse/dist/sparse-0.5.0.tar.gz
tar -xzvf sparse-0.5.0.tar.gz
cd sparse-0.5.0 && make && sudo make install PREFIX=/usr && cd ..
