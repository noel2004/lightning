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
	mingw32-make

## Linux

    mkdir -p build
	cd build
	cmake ../
	make
	
## Android


## iOS
