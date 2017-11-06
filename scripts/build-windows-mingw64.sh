#!/bin/bash

mkdir -p build
cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_SH="CMAKE_SH-NOTFOUND"
cmake --build . --target ccan-configurator
if [ ! -f ccan_config.h ]; then
    ./ccan-configurator gcc > ccan_config.h
fi
cmake --build . --target ln-core

