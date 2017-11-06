# include
# include_directories(include)

# source files
set(SQLITE3_SOURCE_FILE
        sqlite3.c )

# static lib
add_library( sqlite3
             STATIC
             ${SQLITE3_SOURCE_FILE}
             )
