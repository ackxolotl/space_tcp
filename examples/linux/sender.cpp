#include "space_tcp/space_tcp.hpp"

// memory for TUN interface and S3TP endpoint for internal operations
uint8_t tun_buffer[1u << 11u];
uint8_t tcp_buffer[1u << 11u];

// memory for receive/transmit window of connections
uint8_t connection_buffer[1u << 12u];

// connections managed by S3TP endpoint
space_tcp::Connections<1> connections;

auto main() -> int {
    auto tun_config = space_tcp::tun_config{
            .dev_name = "tun1",
            .source_addr = "10.9.8.7",
            .dest_addr = "10.1.2.3"
    };

    // create TUN interface and S3TP endpoint
    auto tun_interface = space_tcp::create_tun_interface(tun_buffer, tun_config);
    auto tcp_endpoint = space_tcp::create_tcp_endpoint(tcp_buffer, tun_interface, connections);

    // create a connection
    auto connection = space_tcp::create_connection(connection_buffer, 117, 105, tcp_endpoint);

    uint8_t message[] = "aloha";

    connection->send(message);

    // run state machine of stack
    while (true) {
        tcp_endpoint.rx(10);
        tcp_endpoint.tx();

        if (connection->get_state() == space_tcp::State::Established && connection->tx_queue_empty()) {
            connection->close();
        }

        if (connection->get_state() == space_tcp::State::Closed) {
            break;
        }
    }

    return 0;
}