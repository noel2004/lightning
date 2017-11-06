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
    cmake .. -G "MinGW Makefiles" -DCMAKE_SH="CMAKE_SH-NOTFOUND"
    cmake --build . --target ln-core

## Linux

    mkdir -p build
    cd build
    cmake ..
    cmake --build . --target ccan-configurator
    cmake ..
    cmake --build . --target ln-core
    
## Android


## iOS
