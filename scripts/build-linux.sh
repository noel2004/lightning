#!/bin/bash

BUILD_DIR="build/linux"
OUTPUT_DIR="output/linux"

rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}
mkdir -p ${BUILD_DIR}

cd ${BUILD_DIR}
cmake .. -DLINUX=1 || exit 1
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator || exit 1
    ./ccan-configurator clang > ccan_config.h
fi
cmake --build . --target lncore || exit 1

cd ../../
cp ${BUILD_DIR}/liblncore.so ${OUTPUT_DIR}/

