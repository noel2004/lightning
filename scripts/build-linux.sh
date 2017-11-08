#!/bin/bash

OUTPUT_DIR="output/mac"
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

mkdir -p build
cd build
cmake .. -DLINUX=1
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator
    ./ccan-configurator clang > ccan_config.h
fi
cmake --build . --target lncore

cd ..

cp build/liblncore.so ${OUTPUT_DIR}/

