# include
include_directories(.)
include_directories (${CMAKE_BINARY_DIR})

# source files
set(LNCORE_SOURCE_FILES
        channel.c
        close_tx.c
        commit_tx.c
        db.c
        failure.c
        htlc.c
        # invoice.c
        lnchannel.c
        lnchannel_api.c
        lnchannel_commit.c
        lnchannel_htlc.c
        lnchannel_open.c
        lnchannel_redeem.c
        log.c
        names.c
        output_to_htlc.c
        permute_tx.c
        pseudorand.c
        secrets.c
        version.c
        )

# static lib
add_library( lightningcore
             STATIC
             ${LNCORE_SOURCE_FILES}
             )

