#!/bin/bash

mkdir -p build
cd build
cmake .. -DLINUX=1
cmake --build . --target ccan-configurator
if [ ! -f ccan_config.h ]; then
    ./ccan-configurator clang > ccan_config.h
fi
cmake --build . --target lncore

