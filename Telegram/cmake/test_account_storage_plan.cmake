# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_account_storage_plan)
init_non_host_target(test_account_storage_plan "(tests)")

nice_target_sources(test_account_storage_plan ${src_loc}
PRIVATE
    ayu/features/profile_sets/account_keyring.cpp
    ayu/features/profile_sets/account_keyring.h
    ayu/features/profile_sets/account_storage_plan.cpp
    ayu/features/profile_sets/account_storage_plan.h
    ayu/features/profile_sets/profile_sets.cpp
    ayu/features/profile_sets/profile_sets.h
    ayu/features/profile_sets/profile_vault.cpp
    ayu/features/profile_sets/profile_vault.h
    storage/storage_account_paths.cpp
    storage/storage_account_paths.h
    tests/test_account_storage_plan.cpp
)

target_include_directories(test_account_storage_plan
PRIVATE
    ${src_loc}
)

target_link_libraries(test_account_storage_plan
PRIVATE
    desktop-app::external_openssl
    desktop-app::lib_ui
)

set_target_properties(test_account_storage_plan PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_account_storage_plan
)
