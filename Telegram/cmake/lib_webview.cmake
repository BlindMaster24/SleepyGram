if (NOT WIN32)
    add_subdirectory(lib_webview)
    return()
endif()

find_package(Git REQUIRED)

set(webview_source "${CMAKE_CURRENT_SOURCE_DIR}/lib_webview")
set(webview_overlay "${CMAKE_CURRENT_BINARY_DIR}/lib_webview-isolated-source")
set(webview_patch "${CMAKE_CURRENT_LIST_DIR}/patches/lib_webview_isolated_storage.patch")

file(COPY "${webview_source}/webview" DESTINATION "${webview_overlay}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${webview_patch}")
foreach (pinned_input IN ITEMS
        "CMakeLists.txt;8d68b4fedfc4fba89d1df815870baf3db703b76e0236ffd1dc7e50b2c3fa52e6"
        "webview/webview_embed.h;905dface61ba0fdf8f122131086de2b7366fcffc1d3b21957be3c6c4bc88e13b"
        "webview/webview_embed.cpp;76c36c241779d78a9e1ad6775f61d5762f5f1fc48ab829af65176aa345ad0e0e"
        "webview/webview_interface.h;26a1d6240587bed88a537b6bca98290af77093886c7949f5685392d9fa745aca"
        "webview/platform/win/webview_win.cpp;4a5ef2e144fda25594135ae3ef4749ee47fcdee9370cc6982c0c1a1dd15ec11e"
        "webview/platform/win/webview_windows_edge_chromium.cpp;5a673a4151cdf332894f91ebeaca8ed54676cddec125477411bcc8c58908074c")
    list(GET pinned_input 0 path)
    list(GET pinned_input 1 expected_sha)
    set(input "${webview_source}/${path}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${input}")
    file(READ "${input}" source_text)
    string(REPLACE "\r\n" "\n" source_text "${source_text}")
    string(SHA256 actual_sha "${source_text}")
    if (NOT actual_sha STREQUAL expected_sha)
        message(FATAL_ERROR "The Windows WebView isolation patch requires lib_webview 0948a2996: ${path}")
    endif()
    file(WRITE "${webview_overlay}/${path}" "${source_text}")
endforeach()

file(READ "${webview_patch}" patch_text)
string(REPLACE "\r\n" "\n" patch_text "${patch_text}")
set(normalized_patch "${webview_overlay}/isolated-storage.patch")
file(WRITE "${normalized_patch}" "${patch_text}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${CMAKE_CURRENT_BINARY_DIR}"
        "${GIT_EXECUTABLE}" apply --no-index --whitespace=nowarn "${normalized_patch}"
    WORKING_DIRECTORY "${webview_overlay}"
    RESULT_VARIABLE patch_result
    ERROR_VARIABLE patch_error)
if (NOT patch_result STREQUAL "0")
    message(FATAL_ERROR "Could not apply the Windows WebView isolation patch: ${patch_error}")
endif()

add_subdirectory("${webview_overlay}" lib_webview)
target_link_libraries(lib_webview PRIVATE advapi32 shlwapi)
