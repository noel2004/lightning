# include
include_directories(.)

# ccan
set(UTILS_SOURCE_FILES
        utils.c
        type_to_string.c
        opt_bits.c
        )

# sqlite
add_library( utils
             STATIC
             ${UTILS_SOURCE_FILES}
             )

