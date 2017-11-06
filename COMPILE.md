# Compile

## Windows (VS2015)

    mkdir -p build
    cd build
    cmake ../
    # open LNCORE.sln in VS2015

## Windows (Mingw64)

    mkdir -p build
    cd build
    cmake .. -G "MinGW Makefiles" -DCMAKE_SH="CMAKE_SH-NOTFOUND"
    cmake --build . --target ccan-configurator
	./ccan-configurator gcc > ccan_config.h
    cmake --build . --target ln-core

## Linux(Clang)

    mkdir -p build
    cd build
    cmake .. -DLINUX=1
    cmake --build . --target ccan-configurator
	./ccan-configurator clang > ccan_config.h
    cmake --build . --target ln-core
    
## Android


## iOS
