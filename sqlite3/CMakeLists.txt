# include
# include_directories(include)

# sqlite
# aux_source_directory(SQLiteCpp/src SQLITECPP_SOURCE_FILES)
set(SQLITE3_SOURCE_FILE
        sqlite3.c )

# sqlite
add_library( sqlite3
             STATIC
             ${SQLITE3_SOURCE_FILE}
             )