#!/bin/bash

BUILD_DIR="build/win"
OUTPUT_DIR="output/win"

rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}
mkdir -p ${BUILD_DIR}

cd ${BUILD_DIR}
cmake .. -G "MinGW Makefiles" -DCMAKE_SH="CMAKE_SH-NOTFOUND" -DWIN=1 -DMINGW64=1 || exit 1
if [ ! -f ccan_config.h ]; then
    cmake --build . --target ccan-configurator || exit 1
    ./ccan-configurator.exe gcc > ccan_config.h
fi
cmake --build . --target lncore || exit 1

cd ../../
cp ${BUILD_DIR}/liblncore.dll ${OUTPUT_DIR}/

