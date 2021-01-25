#ifndef SPACE_TCP_ENDPOINT_HPP
#define SPACE_TCP_ENDPOINT_HPP

#include "connection.hpp"

namespace space_tcp {

class TcpEndpoint {
public:
    // buffer should have the (maximum) size of one S3TP packet
    static auto
    create(uint8_t *buffer, size_t len, ConnectionManager *connections, NetworkInterface &nif) -> TcpEndpoint {
        return {buffer, len, connections, nif};
    }

    auto receive(uint8_t *buffer, size_t len, size_t timeout) -> ssize_t {
        std::cout << "tcp endpoint receive" << std::endl;

        // receive some data from network
        if (network.receive(&*tcp_buffer, buffer_len, timeout / 10) == -1) {
            // could not receive data
            return -1;
        }

        // parse and store received data appropriately in receive window, send reply if needed

        // return amount of received data
        return 1;
    }

    auto send(const uint8_t *buffer, size_t len, size_t timeout) -> ssize_t {
        return sizeof(buffer) + len + timeout;
    }

    auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port) -> Connection * {
        return connections->create_connection(buffer, len, rx_port, tx_port, *this);
    }

private:
    TcpEndpoint(uint8_t *buffer, size_t len, ConnectionManager *connections, NetworkInterface &network) : tcp_buffer{
            buffer}, buffer_len{len}, connections{connections}, network{network} {};

    uint8_t *tcp_buffer;
    size_t buffer_len;

    // list of connections
    ConnectionManager *connections;

    NetworkInterface &network;
};

} // namespace space_tcp

#endif //SPACE_TCP_ENDPOINT_HPP
