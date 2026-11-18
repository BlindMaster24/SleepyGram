# This is the source code of AyuGram for Desktop.

add_executable(test_archive_migration)
init_non_host_target(test_archive_migration "(tests)")

nice_target_sources(test_archive_migration ${src_loc}
PRIVATE
    ayu/data/archive_migration.cpp
    ayu/data/archive_migration.h
    ayu/data/archive_partition.cpp
    ayu/data/archive_partition.h
    ayu/data/archive_sqlcipher.cpp
    ayu/data/archive_sqlcipher.h
    tests/test_archive_migration.cpp
)

target_include_directories(test_archive_migration PRIVATE ${src_loc})
target_link_libraries(test_archive_migration
PRIVATE
    desktop-app::external_openssl
    tdesktop::lib_sqlcipher
)

set_target_properties(test_archive_migration PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_archive_migration
)
