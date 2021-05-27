#ifndef SPACE_TCP_ENDPOINT_HPP
#define SPACE_TCP_ENDPOINT_HPP

#include "connection/connection.hpp"
#include "connection/connection_manager.hpp"
#include "network/network.hpp"

namespace space_tcp {

/// A S3TP endpoint.
class TcpEndpoint {
public:
    /// Creates a new endpoint. Buffer should be at least 572 bytes (maximum
    /// size of S3TP packets: 44 B header + 512 B payload + 16 B padding).
    static auto create(uint8_t *buffer, size_t len, ConnectionManager &connections, NetworkInterface &network) -> TcpEndpoint;

    /// Receives data via a S3TP connection.
    auto receive(Connection *connection) -> ssize_t;

    /// Sends data via a S3TP connection.
    auto send(Connection *connection, const uint8_t *buffer, size_t len, size_t timeout) -> ssize_t;

    /// Creates a new connection for this S3TP endpoint.
    auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port) -> Connection *;

private:
    TcpEndpoint(uint8_t *buffer, size_t len, ConnectionManager &connections, NetworkInterface &network) : tcp_buffer{
            buffer}, buffer_len{len}, connections{connections}, network{network} {};

    uint8_t *tcp_buffer;
    size_t buffer_len;

    // HMAC key
    uint8_t hmac_key[16]{0xc1, 0xc1, 0x44, 0xe3, 0x1f, 0x46, 0xc1, 0xe9, 0xfb, 0x63, 0xef, 0xfc, 0xc6, 0x31, 0xcd, 0xb0};

    // AES key and IV
    uint8_t aes_key[16]{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t aes_iv[16]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // list of connections
    ConnectionManager &connections;

    NetworkInterface &network;
};

}  // namespace space_tcp

#endif //SPACE_TCP_ENDPOINT_HPP
