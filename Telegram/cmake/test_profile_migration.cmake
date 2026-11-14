# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_profile_migration)
init_non_host_target(test_profile_migration "(tests)")

nice_target_sources(test_profile_migration ${src_loc}
PRIVATE
    ayu/features/profile_sets/profile_migration.cpp
    ayu/features/profile_sets/profile_migration.h
    tests/test_profile_migration.cpp
)

target_include_directories(test_profile_migration
PRIVATE
    ${src_loc}
)

target_link_libraries(test_profile_migration
PRIVATE
    desktop-app::external_openssl
    desktop-app::lib_ui
)

set_target_properties(test_profile_migration PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_profile_migration
)
