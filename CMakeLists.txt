
cmake_minimum_required(VERSION 3.4.1)
project(LNCORE)

# Linux
IF (${LINUX})
    set (CMAKE_C_COMPILER "clang")
    set (CMAKE_CXX_COMPILER "clang++")
ENDIF(${LINUX})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fexceptions -fPIC")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
MESSAGE( STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER} )
MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )
MESSAGE( STATUS "CMAKE_CXX_COMPILER: " ${CMAKE_CXX_COMPILER} )
MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} )

# include
include_directories (.)
include_directories (${CMAKE_BINARY_DIR})
include_directories (ccan)
include_directories (libwally-core)

# sub directory
add_subdirectory(bitcoin)
add_subdirectory(btcnetwork)
add_subdirectory(ccan)
add_subdirectory(libwally-core)
add_subdirectory(sqlite3)
add_subdirectory(utils)

# Android
IF (${ANDROID})
    link_directories(${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/)
    find_library( # Sets the name of the path variable.
                  log-lib

                  # Specifies the name of the NDK library that
                  # you want CMake to locate.
                  log )
ENDIF(${ANDROID})

# Generate ccan-configurator
add_executable(
                ccan-configurator
                ccan/tools/configurator/configurator.c
                )

# Use ccan-configurator to generate ccan_config.h
execute_process(COMMAND ccan-configurator ${CMAKE_C_COMPILER} > ccan_config.h)

add_library( # Sets the name of the library.
             ln-core

             # Sets the library as a shared library.
             SHARED

             dummy.c
             )

target_link_libraries( # Specifies the target library.
                       ln-core

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib}
                       "-Wl,--whole-archive"
                       bitcoin
                       btcnetwork
                       ccan
                       sqlite3
                       wally
                       utils
                       "-Wl,--no-whole-archive"
                       )

