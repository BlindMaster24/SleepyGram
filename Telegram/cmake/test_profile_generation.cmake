# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_library(profile_generation_test_support STATIC EXCLUDE_FROM_ALL)
init_non_host_target(profile_generation_test_support "(tests)")

nice_target_sources(profile_generation_test_support ${src_loc}
PRIVATE
    ayu/features/emergency_actions/emergency_action_journal.cpp
    ayu/features/emergency_actions/emergency_action_plan.cpp
    ayu/features/emergency_actions/emergency_execution_capsule.cpp
    ayu/features/emergency_actions/emergency_rule_dispatch.cpp
    ayu/features/emergency_actions/emergency_rule_vault.cpp
    ayu/features/emergency_actions/scoped_account_clear.cpp
    ayu/features/profile_sets/account_gate_table.cpp
    ayu/features/profile_sets/account_keyring.cpp
    ayu/features/profile_sets/account_registry.cpp
    ayu/features/profile_sets/account_storage_plan.cpp
    ayu/features/profile_sets/profile_generation.cpp
    ayu/features/profile_sets/profile_migration.cpp
    ayu/features/profile_sets/profile_revocable_emergency_admission.cpp
    ayu/features/profile_sets/profile_revocable_emergency_bundle.cpp
    ayu/features/profile_sets/profile_revocable_emergency_capability.cpp
    ayu/features/profile_sets/profile_revocable_emergency_rebind.cpp
    ayu/features/profile_sets/profile_revocable_generation.cpp
    ayu/features/profile_sets/profile_revocable_vault.cpp
    ayu/features/profile_sets/profile_sets.cpp
    ayu/features/profile_sets/profile_vault.cpp
    storage/storage_account_paths.cpp
)

target_include_directories(profile_generation_test_support PUBLIC ${src_loc})

target_link_libraries(profile_generation_test_support
PUBLIC
    desktop-app::external_openssl
    desktop-app::lib_ui
)

set_target_properties(profile_generation_test_support PROPERTIES
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
)

foreach(test IN ITEMS
    test_profile_generation
    test_account_gate_table
    test_profile_revocable_emergency_admission
    test_profile_revocable_emergency_capability
    test_profile_revocable_enrollment
    test_profile_revocable_generation
    test_profile_revocable_vault
)
    add_executable(${test} EXCLUDE_FROM_ALL)
    init_non_host_target(${test} "(tests)")
    nice_target_sources(${test} ${src_loc} PRIVATE tests/${test}.cpp)
    target_link_libraries(${test} PRIVATE profile_generation_test_support)
    set_target_properties(${test} PROPERTIES
        EXCLUDE_FROM_DEFAULT_BUILD TRUE
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${test}
    )
endforeach()

add_custom_target(check_revocable_profiles
    COMMAND $<TARGET_FILE:test_profile_generation>
    COMMAND $<TARGET_FILE:test_account_gate_table>
    COMMAND $<TARGET_FILE:test_profile_revocable_emergency_admission>
    COMMAND $<TARGET_FILE:test_profile_revocable_emergency_capability>
    COMMAND $<TARGET_FILE:test_profile_revocable_enrollment>
    COMMAND $<TARGET_FILE:test_profile_revocable_generation>
    COMMAND $<TARGET_FILE:test_profile_revocable_vault>
    VERBATIM
)
set_target_properties(check_revocable_profiles PROPERTIES
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    FOLDER "(tests)"
)
