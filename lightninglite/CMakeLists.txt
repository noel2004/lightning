# include
include_directories(.)
include_directories (${CMAKE_BINARY_DIR})

# source files
set(LNLITE_SOURCE_FILES
        chain_dummy.cpp
        lite_dummy.cpp
        manager_dummy.cpp
        message_dummy.cpp
        payment_dummy.cpp
        watch_dummy.cpp
        )

# static lib
add_library( lightninglite
             STATIC
             ${LNLITE_SOURCE_FILES}
             )
