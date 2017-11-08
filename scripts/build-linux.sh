#!/bin/bash

OUTPUT_DIR="output/linux"
rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

mkdir -p build
cd build
cmake .. -DLINUX=1 || exit 1
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator
    ./ccan-configurator clang > ccan_config.h || exit 1
fi
cmake --build . --target lncore || exit 1

cd ..

cp build/liblncore.so ${OUTPUT_DIR}/

