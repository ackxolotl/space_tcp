#include "protocol/space_tcp.hpp"
#include "space_tcp/connection/connection.hpp"
#include "space_tcp/connection/connection_manager.hpp"
#include "space_tcp/network/network.hpp"
#include "space_tcp/endpoint.hpp"

namespace space_tcp {

// buffer should have the (maximum) size of one S3TP packet
auto TcpEndpoint::create(uint8_t *buffer, size_t len, ConnectionManager *connections, NetworkInterface &nif) -> TcpEndpoint {
    return {buffer, len, connections, nif};
}

auto TcpEndpoint::receive(Connection *connection) -> ssize_t {
    if (network.receive(tcp_buffer, buffer_len) == -1) {
        // no S3TP packet received by endpoint
        return -1;
    }

    auto packet = SpaceTcpPacket::create_unchecked(tcp_buffer, buffer_len);

    // check version, length, HMAC, etc.
    if (!packet.is_valid_packet(hmac_key, sizeof(hmac_key))) {
        // received S3TP packet was not a valid packet :-/
        return -1;
    }

    // decrypt payload with AES128-CBC
    packet.decrypt_payload(aes_key, aes_iv);

    // remove PKCS#7 padding from payload
    packet.depad_payload();

    // copy payload to connection buffer
    for (auto i = 0; i < packet.size(); i++) {
        connection->con_buffer[i] = packet.payload()[i];
    }

    // return payload size
    return packet.size();
}

auto TcpEndpoint::send(Connection *connection, const uint8_t *buffer, size_t len, size_t timeout) -> ssize_t {
    // split and wrap data into SPACE-TCP packet(s) and send on next layer

    // create S3TP packet in transmit buffer
    auto packet = SpaceTcpPacket::create_unchecked(tcp_buffer, buffer_len);

    packet.initialize(connection->src_port, connection->dst_port, connection->seq_num++);

    // connection state?
    connection->tx_state = State::SynSent;
    packet.set_flags(Flag::Syn | Flag::Rst);

    // set payload
    packet.set_payload(buffer, len);

    // pad payload with PKCS#7 such that payload size is a multiple of 16 bytes
    packet.pad_payload();

    // encrypt payload with AES128-CBC
    packet.encrypt_payload(aes_key, aes_iv);

    // update HMAC of S3TP packet
    packet.update_hmac(hmac_key, sizeof(hmac_key));

    if (!packet.is_valid_packet(hmac_key, sizeof(hmac_key))) {
        // this should NEVER happen but who knows
        error("S3TP packet for transmit is invalid");
    }

    // hand packet to network layer
    network.send(tcp_buffer, 44 + packet.size());

    // TODO(hal): check if packet was really sent out

    return 42 + packet.size();
}

auto TcpEndpoint::create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port) -> Connection * {
    return connections->create_connection(buffer, len, rx_port, tx_port, *this);
}

}  // namespace space_tcp
