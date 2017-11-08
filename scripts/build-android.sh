#!/bin/bash

ABIS=("armeabi" "armeabi-v7a" "x86" "arm64-v8a" "x86_64")
PLATFORMS=("android-16" "android-16" "android-16" "android-21" "android-21")
TARGETS=("arm-linux-androideabi" "arm-linux-androideabi" "x86" "aarch64-linux-android" "x86_64")
PREFIXS=("arm-linux-androideabi" "arm-linux-androideabi" "i686-linux-android" "aarch64-linux-android" "x86_64-linux-android")

BUILD_TYPE="Release"

# ANDROID_HOST_TAG
HOST_SYSTEM=$(uname -s)
if [ "${HOST_SYSTEM}" = "Linux" ]; then
    ANDROID_HOST_TAG="linux-x86_64"
elif [ "${HOST_SYSTEM}" = "Darwin" ]; then
    ANDROID_HOST_TAG="darwin-x86_64"
else
    echo "Unknown host system: ${HOST_SYSTEM}, exit."
    exit
fi

# CMAKE_DIRECTORY
if [ -z "${CMAKE_DIRECTORY}" ];then
    CMAKE_DIRECTORY="/build-tools/cmake-3.6.3155560"
    # download url:
    # https://dl.google.com/android/repository/cmake-3.6.3155560-linux-x86_64.zip
    # https://dl.google.com/android/repository/cmake-3.6.3155560-darwin-x86_64.zip
fi

# NDK_DIRECTORY
if [ -z "${NDK_DIRECTORY}" ];then
    NDK_DIRECTORY="/build-tools/android-ndk-r15c"
    # NDK_DIRECTORY="/build-tools/android-ndk-r14b"
    # download url:
    # https://developer.android.com/ndk/downloads/index.html
fi

CI_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
ROOT_DIR="${CI_DIR}/../"

echo "CMAKE_DIRECTORY:  ${CMAKE_DIRECTORY}"
echo "NDK_DIRECTORY:    ${NDK_DIRECTORY}"
echo "CI_DIR:           ${CI_DIR}"
echo "ROOT_DIR:         ${ROOT_DIR}"
echo "ANDROID_HOST_TAG: ${ANDROID_HOST_TAG}"

OUTPUT_DIRECTORY="${ROOT_DIR}/output/android"
BUILD_DIRECTORY="${ROOT_DIR}/build/"
mkdir -p ${OUTPUT_DIRECTORY}
mkdir -p ${BUILD_DIRECTORY}

LIBS_DIRECTORY="${OUTPUT_DIRECTORY}/libs"
SRC_DIRECTORY="${OUTPUT_DIRECTORY}/src"
CMAKE_BIN="${CMAKE_DIRECTORY}/bin/cmake"
NINJA_BIN="${CMAKE_DIRECTORY}/bin/ninja"
TOOLCHAIN_FILE="${NDK_DIRECTORY}/build/cmake/android.toolchain.cmake"

clean_output() {
    rm -rf "${LIBS_DIRECTORY}" "${SRC_DIRECTORY}" "${BUILD_DIRECTORY}"
}

build_so() {
    ANDROID_ABI=$1
    ANDROID_PLATFORM=$2
    mkdir -p "${BUILD_DIRECTORY}/${ANDROID_ABI}/"
    cd "${BUILD_DIRECTORY}/${ANDROID_ABI}/" || exit

    ${CMAKE_BIN} -G"Android Gradle - Ninja" \
        -DANDROID_ABI="${ANDROID_ABI}" \
        -DANDROID_NDK="${NDK_DIRECTORY}" \
        -DCMAKE_LIBRARY_OUTPUT_DIRECTORY="${LIBS_DIRECTORY}/${ANDROID_ABI}" \
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        -DCMAKE_MAKE_PROGRAM="${NINJA_BIN}" \
        -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
        -DANDROID_PLATFORM="${ANDROID_PLATFORM}" \
        -DANDROID_STL="gnustl_static" \
        -DCMAKE_CXX_FLAGS="-std=c++11 -fexceptions -DANDROID=1" \
        "${ROOT_DIR}" || exit

    ${NINJA_BIN} || exit
}

strip_so() {
    ANDROID_ABI=$1
    TARGET=$2
    PREFIX=$3

    STRIP_BIN="${NDK_DIRECTORY}/toolchains/${TARGET}-4.9/prebuilt/${ANDROID_HOST_TAG}/bin/${PREFIX}-strip"
    echo "${STRIP_BIN}"

    ${STRIP_BIN} "${LIBS_DIRECTORY}/${ANDROID_ABI}/"*.so
}

command_exists () {
    type "$1" &> /dev/null ;
}

# clean output
echo "Clean previous build files and output files..."
clean_output

# build dynamic libraries for all ABIs
for ((i=0; i < ${#ABIS[@]}; i++))
do
    if [[ $# -eq 0 ]] || [[ "$1" == "${ABIS[i]}" ]]; then

        # build so
        echo "Building dynamic library for ${ABIS[i]}..."
        build_so "${ABIS[i]}" "${PLATFORMS[i]}"

        # strip so
        strip_so "${ABIS[i]}" "${TARGETS[i]}" "${PREFIXS[i]}"
    fi
done

# tar sdk.tar.gz
# mkdir -p "${SRC_DIRECTORY}"/main/java/com/taiyiyun/tyimlib/core
# cp "${ROOT_DIR}"/app/src/main/java/com/taiyiyun/tyimlib/core/* \
    # "${SRC_DIRECTORY}"/main/java/com/taiyiyun/tyimlib/core/ -r

# cd "${ROOT_DIR}" || exit
# rm -rf "${ROOT_DIR}/sdk.tar.gz" && tar cvfz "${ROOT_DIR}/sdk.tar.gz" sdk

