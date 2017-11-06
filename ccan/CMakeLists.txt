# include
# include_directories(include)

# ccan
set(CCAN_SOURCE_FILES
        ccan/order/order.c
        ccan/autodata/autodata.c
        ccan/ptr_valid/ptr_valid.c
        ccan/crypto/hkdf_sha256/hkdf_sha256.c
        ccan/crypto/sha256/sha256.c
        ccan/crypto/sha256/benchmarks/double-sha-bench.c
        ccan/crypto/shachain/shachain.c
        ccan/crypto/shachain/tools/shachain48.c
        ccan/crypto/ripemd160/ripemd160.c
        ccan/crypto/hmac_sha256/hmac_sha256.c
        ccan/crypto/siphash24/siphash24.c
        ccan/htable/htable.c
        ccan/htable/tools/hsearchspeed.c
        ccan/htable/tools/stringspeed.c
        ccan/htable/tools/speed.c
        ccan/time/time.c
        ccan/strmap/strmap.c
        ccan/opt/usage.c
        ccan/opt/helpers.c
        ccan/opt/parse.c
        ccan/opt/opt.c
        ccan/pipecmd/pipecmd.c
        ccan/asort/asort.c
        ccan/fdpass/fdpass.c
        ccan/list/list.c
        ccan/err/err.c
        ccan/likely/likely.c
        ccan/io/fdpass/fdpass.c
        ccan/io/benchmarks/run-length-prefix.c
        ccan/io/benchmarks/run-loop.c
        ccan/io/benchmarks/run-different-speed.c
        ccan/io/poll.c
        ccan/io/io.c
        ccan/timer/benchmarks/expected-usage.c
        ccan/timer/benchmarks/benchmark.c
        ccan/timer/timer.c
        ccan/tal/grab_file/grab_file.c
        ccan/tal/benchmark/samba-allocs.c
        ccan/tal/benchmark/speed.c
        ccan/tal/path/path.c
        ccan/tal/str/str.c
        ccan/tal/tal.c
        ccan/intmap/intmap.c
        ccan/breakpoint/breakpoint.c
        ccan/read_write_all/read_write_all.c
        ccan/noerr/noerr.c
        ccan/take/take.c
        ccan/isaac/isaac.c
        ccan/isaac/isaac64.c
        ccan/str/debug.c
        ccan/str/str.c
        ccan/str/hex/hex.c
        ccan/cdump/cdump.c
        ccan/cdump/tools/cdump-enumstr.c
        ccan/mem/mem.c
        ccan/mem/bench/speed.c
        ccan/ilog/ilog.c
        tools/configurator/configurator.c
        )

# sqlite
add_library( ccan
             STATIC
             ${CCAN_SOURCE_FILES}
             )
