# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_account_registry)
init_non_host_target(test_account_registry "(tests)")

nice_target_sources(test_account_registry ${src_loc}
PRIVATE
    ayu/features/profile_sets/account_registry.cpp
    ayu/features/profile_sets/account_registry.h
    ayu/features/profile_sets/profile_sets.cpp
    ayu/features/profile_sets/profile_sets.h
    tests/test_account_registry.cpp
)

target_include_directories(test_account_registry
PRIVATE
    ${src_loc}
)

target_link_libraries(test_account_registry
PRIVATE
    desktop-app::external_openssl
    desktop-app::lib_ui
)

set_target_properties(test_account_registry PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_account_registry
)
