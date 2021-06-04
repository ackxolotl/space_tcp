# Tests for ring.hpp
add_executable(ring ring.cpp)
target_link_libraries(ring gtest gtest_main Threads::Threads space_tcp)
add_test(NAME ring COMMAND ring)

# Tests for segment.hpp
add_executable(segment segment.cpp)
target_link_libraries(segment gtest gtest_main Threads::Threads space_tcp)
add_test(NAME segment COMMAND segment)

# Tests for crypto/aes128.hpp
add_executable(aes128 aes128.cpp)
target_link_libraries(aes128 gtest gtest_main Threads::Threads space_tcp)
add_test(NAME aes128 COMMAND aes128)

# Tests for crypto/sha256.hpp
add_executable(sha256 sha256.cpp)
target_link_libraries(sha256 gtest gtest_main Threads::Threads space_tcp)
add_test(NAME sha256 COMMAND sha256)

# Tests for crypto/hmac.hpp
add_executable(hmac hmac.cpp)
target_link_libraries(hmac gtest gtest_main Threads::Threads space_tcp)
add_test(NAME hmac COMMAND hmac)

# Tests for protocol/ip.hpp
add_executable(ipv4 ip.cpp)
target_link_libraries(ipv4 gtest gtest_main Threads::Threads space_tcp)
add_test(NAME ipv4 COMMAND ipv4)

# Tests for protocol/space_tcp.hpp
add_executable(s3tp space_tcp.cpp)
target_link_libraries(s3tp gtest gtest_main Threads::Threads space_tcp)
add_test(NAME s3tp COMMAND s3tp)

# Tests for endpoint.cpp
add_executable(endpoint endpoint.cpp)
target_link_libraries(endpoint gtest gtest_main Threads::Threads space_tcp)
add_test(NAME endpoint COMMAND endpoint)