# include
include_directories(.)

# source files
set(BTCNETWORK_SOURCE_FILES
        # c/bitcoind.c
        # c/chaintopology.c
        c/watch.c
        )

# static lib
add_library( btcnetwork
             STATIC
             ${BTCNETWORK_SOURCE_FILES}
             )
