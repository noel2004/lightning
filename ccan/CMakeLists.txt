# include
include_directories(.)

# source files
set(CCAN_SOURCE_FILES
        ccan/autodata/autodata.c
        ccan/crypto/sha256/sha256.c
        ccan/crypto/shachain/shachain.c
        ccan/crypto/ripemd160/ripemd160.c
        ccan/crypto/siphash24/siphash24.c
        ccan/htable/htable.c
        ccan/time/time.c
        ccan/strmap/strmap.c
        ccan/opt/usage.c
        ccan/opt/helpers.c
        ccan/opt/parse.c
        ccan/opt/opt.c
        ccan/err/err.c
        # ccan/io/poll.c
        # ccan/io/io.c
        ccan/timer/timer.c
        # ccan/tal/grab_file/grab_file.c
        # ccan/tal/path/path.c
        ccan/tal/str/str.c
        ccan/tal/tal.c
        ccan/intmap/intmap.c
        # ccan/breakpoint/breakpoint.c
        ccan/read_write_all/read_write_all.c
        ccan/noerr/noerr.c
        ccan/take/take.c
        ccan/isaac/isaac.c
        ccan/isaac/isaac64.c
        ccan/str/debug.c
        ccan/str/str.c
        ccan/str/hex/hex.c
        ccan/cdump/cdump.c
        ccan/mem/mem.c
        ccan/ilog/ilog.c
        ccan/list/list.c
        )

IF(NOT DEFINED ${WIN})
    set(CCAN_SOURCE_FILES
            ${CCAN_SOURCE_FILES}
            ccan/ptr_valid/ptr_valid.c
            )
ENDIF()

# static lib
add_library( ccan
             STATIC
             ${CCAN_SOURCE_FILES}
             )
