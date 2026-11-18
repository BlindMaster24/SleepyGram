# This is the source code of AyuGram for Desktop.

add_library(lib_sqlcipher STATIC)
init_target(lib_sqlcipher "(external)")

add_library(tdesktop::lib_sqlcipher ALIAS lib_sqlcipher)

nice_target_sources(lib_sqlcipher ${src_loc}/ayu/libs/sqlite
PRIVATE
    sqlite3.c
    sqlite3.h
)

set_target_properties(lib_sqlcipher PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS ON
    C_VISIBILITY_PRESET hidden
)

target_compile_definitions(lib_sqlcipher
PUBLIC
    SQLITE_HAS_CODEC
PRIVATE
    SQLCIPHER_CRYPTO_OPENSSL=1
    SQLITE_EXTRA_INIT=sqlcipher_extra_init
    SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
    SQLITE_OMIT_LOAD_EXTENSION=1
    SQLITE_TEMP_STORE=3
    SQLITE_THREADSAFE=1
)

find_package(Threads REQUIRED)

target_link_libraries(lib_sqlcipher
PRIVATE
    desktop-app::external_openssl
    Threads::Threads
)

if (MSVC)
    add_library(lib_sqlcipher_warnings_off INTERFACE)
    target_compile_options(lib_sqlcipher_warnings_off INTERFACE /W0 /WX-)
    target_link_libraries(lib_sqlcipher PRIVATE lib_sqlcipher_warnings_off)
else()
    target_compile_options(lib_sqlcipher PRIVATE -w)
endif()
