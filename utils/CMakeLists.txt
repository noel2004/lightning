# include
include_directories(.)

# source files
set(UTILS_SOURCE_FILES
        utils.c
        sodium/utils.c
        sodium/randombytes.c
        sodium/randombytes_sysrandom.c
        type_to_string.c
        opt_bits.c
        )

# static lib
add_library( utils
             STATIC
             ${UTILS_SOURCE_FILES}
             )

