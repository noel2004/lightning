# include
include_directories(.)
include_directories (${CMAKE_BINARY_DIR})

# source files
set(LNLITE_SOURCE_FILES
        chain_dummy.cpp
        lite_demo.cpp
        manager_st.cpp
        message_demo.cpp
        payment_dummy.cpp
        # payment_st.cpp
        watch_demo.cpp
        )

# static lib
add_library( lightninglite
             STATIC
             ${LNLITE_SOURCE_FILES}
             )
