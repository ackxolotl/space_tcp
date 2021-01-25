#include <iostream>

// TODO: remove this
#include <space_tcp.hpp>

#include "space_tcp/space_tcp.hpp"

// memory for TUN interface and space TCP endpoint for internal operations
uint8_t tun_buffer[1u << 12u];
uint8_t tcp_buffer[1u << 11u];

// memory for receive/transmit window of connections
uint8_t connection1_buffer[1u << 12u];
uint8_t connection2_buffer[1u << 12u];

// connections managed by space TCP endpoint
space_tcp::Connections<2> connections;

auto main() -> int {
    // buffer for received data
    uint8_t receive_buffer[1u << 12u];

    // create TUN interface and space TCP endpoint
    auto tun_interface = space_tcp::create_tun_interface(tun_buffer);
    auto tcp_endpoint = space_tcp::create_tcp_endpoint(tcp_buffer, tun_interface, connections);

    // create a connection
    auto connection = space_tcp::create_connection(connection1_buffer, 117, 105, tcp_endpoint);

    if (!connection) {
        std::cerr << "no connection :-/" << std::endl;
        std::exit(1);
    }

    // receive data into receive buffer
    connection->receive(receive_buffer);

    // transmit data
    uint8_t message[] = {'m', 'e', 's', 's', 'a', 'g', 'e'};
    connection->send(message);

    // create another connection
    auto connection2 = space_tcp::create_connection(connection2_buffer, 117, 105, tcp_endpoint);

    if (!connection2) {
        std::cerr << "no connection :-/" << std::endl;
        std::exit(1);
    }

    // receive data into receive buffer
    connection2->receive(receive_buffer);

    return 0;
}