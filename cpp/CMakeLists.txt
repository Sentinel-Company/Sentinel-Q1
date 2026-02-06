cmake_minimum_required(VERSION 3.20)
project(NovaHybrid CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build Rust library first
# MSVC: target/release/nova_core.lib (statik)
set(RUST_TARGET_DIR "${CMAKE_SOURCE_DIR}/../target")
if(WIN32)
    set(RUST_LIB "${RUST_TARGET_DIR}/release/nova_core.lib")
else()
    set(RUST_LIB "${RUST_TARGET_DIR}/release/libnova_core.a")
endif()

add_custom_command(
    OUTPUT ${RUST_LIB}
    COMMAND cargo build --release
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/..
    COMMENT "Building Rust Core Engine..."
)

add_custom_target(rust_core ALL DEPENDS ${RUST_LIB})

# C++ executable
add_executable(nova_hybrid
    src/main.cpp
    src/strategy_engine/strategy_engine.cpp
)

target_include_directories(nova_hybrid PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

get_filename_component(RUST_LIB_DIR ${RUST_LIB} DIRECTORY)
target_link_directories(nova_hybrid PRIVATE ${RUST_LIB_DIR})
target_link_libraries(nova_hybrid PRIVATE nova_core)

# Link system libs for Rust (Windows: bcrypt, userenv, etc.)
if(WIN32)
    target_link_libraries(nova_hybrid PRIVATE
        bcrypt
        userenv
        ws2_32
    )
else()
    target_link_libraries(nova_hybrid PRIVATE
        dl
        pthread
    )
endif()

add_dependencies(nova_hybrid rust_core)
