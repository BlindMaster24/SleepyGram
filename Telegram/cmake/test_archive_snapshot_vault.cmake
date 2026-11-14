# This is the source code of AyuGram for Desktop.

add_executable(test_archive_snapshot_vault)
init_non_host_target(test_archive_snapshot_vault "(tests)")

nice_target_sources(test_archive_snapshot_vault ${src_loc}
PRIVATE
    ayu/data/archive_snapshot_vault.cpp
    ayu/data/archive_snapshot_vault.h
    ayu/data/ayu_database.h
    ayu/data/entities.h
    ayu/features/profile_sets/account_keyring.h
    ayu/features/profile_sets/profile_sets.h
    tests/test_archive_snapshot_vault.cpp
)

target_include_directories(test_archive_snapshot_vault
PRIVATE
    ${src_loc}
)

target_link_libraries(test_archive_snapshot_vault
PRIVATE
    desktop-app::external_openssl
    desktop-app::lib_ui
)

set_target_properties(test_archive_snapshot_vault PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_archive_snapshot_vault
)
