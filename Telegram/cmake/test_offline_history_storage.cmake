# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

add_executable(test_offline_history_storage)
init_non_host_target(test_offline_history_storage "(tests)")

nice_target_sources(test_offline_history_storage ${src_loc}
PRIVATE
    ayu/features/offline_history/offline_history_storage.cpp
    ayu/features/offline_history/offline_history_storage.h
    tests/test_offline_history_storage.cpp
)

target_include_directories(test_offline_history_storage
PRIVATE
    ${src_loc}
)

target_link_libraries(test_offline_history_storage
PRIVATE
    desktop-app::lib_ui
)

set_target_properties(test_offline_history_storage PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test_offline_history_storage
)
