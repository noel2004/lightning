# Compile

## Windows (VS2015)

    mkdir -p build-vs
	cd build-vs
	cmake ../
	# open LNCORE.sln in VS2015

## Windows (Mingw64)

    mkdir -p build-mingw
	cd mingw
    cmake .. -G "MinGW Makefiles" -DCMAKE_SH="CMAKE_SH-NOTFOUND"
	mingw32-make

## Linux

    mkdir -p build-vs
	cd build-vs
	cmake ../
	make
	
## Android


## iOS
