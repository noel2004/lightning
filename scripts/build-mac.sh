#!/bin/bash

OUTPUT_DIR="output/mac"
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

mkdir -p build
cd build
cmake .. -DMAC=1 || exit 1
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator || exit 1
    ./ccan-configurator clang > ccan_config.h
fi
cmake --build . --target lncore || exit 1

cd ..

cp build/liblncore.liblncore.dylib ${OUTPUT_DIR}/

