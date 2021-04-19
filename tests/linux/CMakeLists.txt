# Tests for crypto/sha256.hpp
add_executable(sha256 sha256.cpp)
target_link_libraries(sha256 gtest gtest_main Threads::Threads space_tcp)
add_test(NAME sha256 COMMAND sha256)

# Tests for protocol/ip.hpp
add_executable(ipv4 ip.cpp)
target_link_libraries(ipv4 gtest gtest_main Threads::Threads space_tcp)
add_test(NAME ipv4 COMMAND ipv4)