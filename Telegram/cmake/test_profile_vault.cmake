# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_profile_vault)
init_non_host_target(test_profile_vault "(tests)")

nice_target_sources(test_profile_vault ${src_loc}
PRIVATE
    ayu/features/profile_sets/account_keyring.cpp
    ayu/features/profile_sets/account_keyring.h
    ayu/features/profile_sets/profile_sets.cpp
    ayu/features/profile_sets/profile_sets.h
    ayu/features/profile_sets/profile_vault.cpp
    ayu/features/profile_sets/profile_vault.h
    tests/test_profile_vault.cpp
)

target_include_directories(test_profile_vault
PRIVATE
    ${src_loc}
)

target_link_libraries(test_profile_vault
PRIVATE
    desktop-app::external_openssl
    desktop-app::lib_ui
)

set_target_properties(test_profile_vault PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_profile_vault
)
