add_executable(sender sender.cpp)
target_link_libraries(sender PRIVATE space_tcp)

add_executable(receiver receiver.cpp)
target_link_libraries(receiver PRIVATE space_tcp)