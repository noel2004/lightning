cmake_minimum_required(VERSION 3.4.1)
project(LNCORE)

# PLATFORM

## Linux
IF(${LINUX})
    MESSAGE(STATUS "USE LINUX CONFIG")
    set (CMAKE_C_COMPILER "clang")
    set (CMAKE_CXX_COMPILER "clang++")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set (WHOLE_ARCHIVE_START "-Wl,--whole-archive")
    set (WHOLE_ARCHIVE_END "-Wl,--no-whole-archive")
ENDIF()

## MAC
IF(${MAC})
    MESSAGE(STATUS "USE MAC CONFIG")
    set (CMAKE_C_COMPILER "clang")
    set (CMAKE_CXX_COMPILER "clang++")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set (WHOLE_ARCHIVE_START "-all_load")
    set (WHOLE_ARCHIVE_END "")
ENDIF()

## Windows
IF(${WIN})
    IF(${MINGW64}) # Mingw64
        MESSAGE(STATUS "USE WINDOWS MINGW64 CONFIG")
        set (CMAKE_C_COMPILER "gcc")
        set (CMAKE_CXX_COMPILER "g++")
        set (WHOLE_ARCHIVE_START "-Wl,--whole-archive")
        set (WHOLE_ARCHIVE_END "-Wl,--no-whole-archive")
    ELSE() # MSVS
        MESSAGE(STATUS "USE WINDOWS MSVS CONFIG")
    ENDIF()
ENDIF()

## Android
IF (${ANDROID})
    MESSAGE(STATUS "USE ANDROID CONFIG")
    set (WHOLE_ARCHIVE_START "-Wl,--whole-archive")
    set (WHOLE_ARCHIVE_END "-Wl,--no-whole-archive")
    link_directories(${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/)
    find_library( # Sets the name of the path variable.
                  log-lib

                  # Specifies the name of the NDK library that
                  # you want CMake to locate.
                  log )
ENDIF(${ANDROID})

## iOS
IF (${IOS})
    MESSAGE(STATUS "USE IOS CONFIG")
ENDIF()

# PLATFORM END

# Compile config
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fexceptions")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

MESSAGE( STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER} )
MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )
MESSAGE( STATUS "CMAKE_CXX_COMPILER: " ${CMAKE_CXX_COMPILER} )
MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} )

# include
include_directories (.)
include_directories (${CMAKE_BINARY_DIR})
include_directories (ccan)
include_directories (libwally-core)
include_directories (sqlite3)

# sub directory
add_subdirectory(bitcoin)
add_subdirectory(btcnetwork)
add_subdirectory(ccan)
add_subdirectory(lightningcore)
add_subdirectory(lightninglite)
add_subdirectory(sqlite3)
add_subdirectory(utils)

add_subdirectory(libwally-core)

# Generate ccan-configurator
add_executable(
                ccan-configurator
                ccan/tools/configurator/configurator.c
                )

# Generate wally
add_library( # Sets the name of the library.
             wally

             # Sets the library as a shared library.
             SHARED

             dummy.c
             )

target_link_libraries( # Specifies the target library.
                       wally

                       ${log-lib}
                       ${WHOLE_ARCHIVE_START}
                       wallystatic
                       ${WHOLE_ARCHIVE_END}
                       )

# Generate lncore
add_library( # Sets the name of the library.
             lncore

             # Sets the library as a shared library.
             SHARED

             dummy.c
             )

target_link_libraries( # Specifies the target library.
                       lncore

                       ${log-lib}
                       ${WHOLE_ARCHIVE_START}
                       bitcoin
                       btcnetwork
                       ccan
                       lightningcore
                       lightninglite
                       sqlite3
                       utils
                       wally
                       ${WHOLE_ARCHIVE_END}
                       )

