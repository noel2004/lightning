#!/bin/bash

mkdir -p build
cd build
cmake .. -DLINUX=1
cmake --build . --target ccan-configurator
./ccan-configurator clang > ccan_config.h
cmake --build . --target ln-core

