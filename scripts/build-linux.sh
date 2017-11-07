#!/bin/bash

mkdir -p build
cd build
cmake .. -DLINUX=1
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator
    ./ccan-configurator clang > ccan_config.h
fi
cmake --build . --target lncore

