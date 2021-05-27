cmake_minimum_required(VERSION 3.19)
project(space_tcp
        VERSION 0.1
        DESCRIPTION "S3TP - a simple stupid satellite transport protocol"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_compile_options(
        -Wall
        -Wextra
        -pedantic
        -Wno-unused-parameter
        -Wno-unused-function
        -Wformat=2
)

# external dependencies
add_subdirectory(subprojects/tiny-AES-c)

# space_tcp library
add_library(${PROJECT_NAME} src/crypto/aes128.cpp src/network/tun.cpp src/endpoint.cpp src/rand.cpp src/time.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include PUBLIC ${PROJECT_SOURCE_DIR}/src)

# link space_tcp with external dependencies
target_link_libraries(${PROJECT_NAME} PRIVATE tiny-aes)

# examples
add_subdirectory(examples/linux)

# documentation
add_subdirectory(doc)

# tests
enable_testing()
add_subdirectory(tests)