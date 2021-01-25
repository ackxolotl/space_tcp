cmake_minimum_required(VERSION 3.19)
project(space_tcp
        VERSION 0.1
        DESCRIPTION "S3TP - a simple stupid satellite transport protocol"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

add_compile_options(
        -Wall
        -Wextra
        -pedantic
        -Wno-unused-parameter
        -Wno-unused-function
        -Wformat=2
)

add_library(space_tcp src/space_tcp.cpp)
# FIXME: PUBLIC -> PRIVATE
target_include_directories(space_tcp PUBLIC ${PROJECT_SOURCE_DIR}/include PUBLIC ${PROJECT_SOURCE_DIR}/src)

add_subdirectory(examples/linux)
