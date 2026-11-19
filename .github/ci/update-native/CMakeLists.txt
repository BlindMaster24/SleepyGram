cmake_minimum_required(VERSION 3.25)
project(SleepyGramUpdateTools LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(LibLZMA REQUIRED)
find_package(ZLIB REQUIRED)

get_filename_component(root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(sources "${root}/Telegram/SourceFiles")
set(SLEEPYGRAM_LIB_BASE_DIR "${root}/Telegram/lib_base" CACHE PATH "lib_base source tree")
set(keys "${root}/Telegram/Resources/update/sleepygram-test")
set(keys_header "${CMAKE_CURRENT_BINARY_DIR}/update_keys_data.h")
set(keys_script "${root}/Telegram/cmake/update_keys_header.cmake")

add_custom_command(OUTPUT "${keys_header}"
    COMMAND "${CMAKE_COMMAND}"
        "-Droot_pem=${keys}/root-public.pem"
        "-Dmanifest=${keys}/manifest.min.json"
        "-Dmanifest_sig=${keys}/manifest.sig"
        "-Doutput=${keys_header}"
        -P "${keys_script}"
    DEPENDS "${keys_script}" "${keys}/root-public.pem"
        "${keys}/manifest.min.json" "${keys}/manifest.sig"
    VERBATIM
)

add_executable(Updater
    "${sources}/_other/sleepy_updater.cpp"
    "${sources}/core/sleepy_update_install.cpp"
    "${sources}/core/update_keys.cpp"
    "${sources}/core/update_unpack.cpp"
    "${sources}/core/update_verify.cpp"
    "${keys_header}"
)
target_compile_features(Updater PRIVATE cxx_std_20)
target_include_directories(Updater PRIVATE "${sources}"
    "${CMAKE_CURRENT_BINARY_DIR}" "${SLEEPYGRAM_LIB_BASE_DIR}")
target_link_libraries(Updater PRIVATE Qt6::Core OpenSSL::Crypto LibLZMA::LibLZMA)

add_executable(Packer
    "${sources}/_other/packer.cpp"
    "${sources}/core/update_verify.cpp"
)
target_compile_features(Packer PRIVATE cxx_std_20)
target_compile_definitions(Packer PRIVATE PACKER_DISABLE_PRIVATE)
target_include_directories(Packer PRIVATE "${sources}")
target_link_libraries(Packer PRIVATE Qt6::Core OpenSSL::Crypto LibLZMA::LibLZMA ZLIB::ZLIB)
