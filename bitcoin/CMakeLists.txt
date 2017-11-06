# include
include_directories(.)

# ccan
set(BITCOIN_SOURCE_FILES
        varint.c
        base58.c
        pullpush.c
        shadouble.c
        locktime.c
        block.c
        script.c
        tx.c
        signature.c
        simple.c
        pubkey.c
        )

# sqlite
add_library( bitcoin
             STATIC
             ${BITCOIN_SOURCE_FILES}
             )
