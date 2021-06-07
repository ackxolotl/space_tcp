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

    /// Makes the endpoint process incoming packets.
    void rx(ssize_t timeout = -1);

    /// Makes the endpoint transmit outgoing packets.
    void tx(ssize_t timeout = -1);

    /// Creates a new connection for this S3TP endpoint.
    auto create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port) -> Connection *;

private:
    TcpEndpoint(uint8_t *buffer, size_t len, ConnectionManager &connections, NetworkInterface &network) : tcp_buffer{
            buffer}, buffer_len{len}, connections{connections}, network{network} {};

    uint8_t *tcp_buffer;
    size_t buffer_len;

    // HMAC key
    uint8_t hmac_key[16]{0x85, 0xB1, 0x52, 0x97, 0x10, 0xE1, 0x7C, 0xB5, 0x51, 0xF5, 0x51, 0xD3, 0x2F, 0x72, 0x9D, 0x06};

    // AES key and IV
    uint8_t aes_key[16]{0xBE, 0x41, 0x27, 0x89, 0xF8, 0x18, 0x49, 0x48, 0x60, 0xCA, 0x9F, 0x42, 0x73, 0x27, 0x02, 0xD8};
    uint8_t aes_iv[16]{0x20, 0x2F, 0x82, 0x2D, 0xE1, 0xE4, 0x05, 0xA6, 0x1A, 0x3F, 0x61, 0xE0, 0x6D, 0xE8, 0x13, 0x8F};

    // list of connections
    ConnectionManager &connections;

    // next tx connection to check
    size_t next_tx_connection{};

    NetworkInterface &network;
};

}  // namespace space_tcp

#endif //SPACE_TCP_ENDPOINT_HPP
