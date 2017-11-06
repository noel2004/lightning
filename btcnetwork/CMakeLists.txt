# include
include_directories(.)

# ccan
set(BTCNETWORK_SOURCE_FILES
        # c/bitcoind.c
        # c/chaintopology.c
        c/watch.c
        )

# sqlite
add_library( btcnetwork
             STATIC
             ${BTCNETWORK_SOURCE_FILES}
             )
