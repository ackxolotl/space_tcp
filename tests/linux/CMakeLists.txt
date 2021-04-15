# Add tests
add_executable(some_test some_test.cpp)
target_link_libraries(some_test gtest gtest_main Threads::Threads)
add_test(NAME some_test COMMAND some_test)