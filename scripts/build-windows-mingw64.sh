#!/bin/bash

mkdir -p build
cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_SH="CMAKE_SH-NOTFOUND"
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator
    ./ccan-configurator.exe gcc > ccan_config.h
fi
cmake --build . --target lncore

