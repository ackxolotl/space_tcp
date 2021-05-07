#include <iostream>

#include "space_tcp/space_tcp.hpp"

// memory for TUN interface and S3TP endpoint for internal operations
uint8_t tun_buffer[1u << 11u];
uint8_t tcp_buffer[1u << 11u];

// memory for receive/transmit window of connections
uint8_t connection_buffer[1u << 12u];

// connections managed by S3TP endpoint
space_tcp::Connections<1> connections;

auto main() -> int {
    // buffer for received data
    uint8_t receive_buffer[1u << 12u]{};

    auto tun_config = space_tcp::tun_config{
            .timeout = -1, // TUN interface waits infinitely for messages
            .dev_name = "tun0",
            .source_addr = "10.1.2.3",
            .dest_addr = "10.9.8.7"
    };

    // create TUN interface and S3TP endpoint
    auto tun_interface = space_tcp::create_tun_interface(tun_buffer, tun_config);
    auto tcp_endpoint = space_tcp::create_tcp_endpoint(tcp_buffer, tun_interface, connections);

    // create a connection
    auto connection = space_tcp::create_connection(connection_buffer, 105, 117, tcp_endpoint);

    // receive data into receive buffer
    for (auto i = 0; i < 512; i++) {
        if (connection->receive(receive_buffer) > 0) {
            std::cout << "Received message: " << receive_buffer << std::endl;
            memset(receive_buffer, 0, sizeof(receive_buffer));
        }
    }

    return 0;
}