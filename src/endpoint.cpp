#include "space_tcp/endpoint.hpp"
#include "protocol/space_tcp.hpp"
#include "space_tcp/connection/connection.hpp"
#include "space_tcp/connection/connection_manager.hpp"
#include "space_tcp/network/network.hpp"

#define PAYLOAD_SIZE 512
#define WINDOW_SIZE 32

// cool-off period for closing connections in seconds
#define TIMEWAIT    10


namespace space_tcp {

// buffer should have the (maximum) size of one S3TP packet
auto TcpEndpoint::create(uint8_t *buffer, size_t len, ConnectionManager &connections, NetworkInterface &network) -> TcpEndpoint {
    return {buffer, len, connections, network};
}

void TcpEndpoint::rx(ssize_t timeout) {
    if (network.receive(tcp_buffer, buffer_len, timeout) == -1) {
        // no S3TP packet received by endpoint
        return;
    }

    auto packet = SpaceTcpPacket::create_unchecked(tcp_buffer, buffer_len);

    // check version, length, HMAC, etc.
    if (!packet.is_valid_packet(hmac_key, sizeof(hmac_key))) {
        // received S3TP packet was not a valid packet :-/
        return;
    }

    if (packet.size() > 0) {
        // decrypt payload with AES128-CBC
        packet.decrypt_payload(aes_key, aes_iv);

        // remove PKCS#7 padding from payload
        packet.depad_payload();
    }

    // find connection
    auto src_port = packet.src_port();
    auto dst_port = packet.dst_port();
    auto connection = connections.find_connection(dst_port, src_port);

    if (!connection) {
        warn("received S3TP packet does not belong to any connection");

        return;
    }

    if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
        return;
    }

    auto send_packet = false;

    switch (connection->state) {
        case State::Closed: {
            // TODO(hal): send RST

            break;
        }
        case State::Listen: {
            if ((packet.flags() & Flag::Syn) != Flag::Syn) {
                return;
            }

            auto seq_num = packet.seq_num();
            auto to_ack_num = seq_num + packet.size() + 1;

            connection->state = State::SynReceived;
            connection->rx_initial_seq_num = seq_num;
            connection->rx_next_seq_num = to_ack_num;

            // get payload data
            connection->receive_buffer.push_back(packet.payload(), packet.size());

            send_packet = true;

            auto len = connection->transmit_buffer.used_space();
            len = (len > PAYLOAD_SIZE) ? PAYLOAD_SIZE : len;

            uint8_t data[PAYLOAD_SIZE]{0};
            connection->transmit_buffer.copy(data, len);

            // send SYN+ACK on SYN
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
            packet.set_flags(Flag::Syn | Flag::Ack);
            packet.set_ack_num(to_ack_num);
            packet.set_payload(data, len);

            connection->tx_next_seq_num += packet.size() + 1;
            connection->rx_acked = to_ack_num;

            connection->tx_last_time = Time::get_time_in_ms();

            break;
        }
        case State::SynSent: {
            if ((packet.flags() & (Flag::Syn | Flag::Ack)) != (Flag::Syn | Flag::Ack)) {
                return;
            }

            if (connection->tx_unacked >= packet.ack_num() || connection->tx_next_seq_num < packet.ack_num()) {
                debug("SYN+ACK acknowledges wrong sequence number");
            }

            auto seq_num = packet.seq_num();

            auto acknowledged_data = packet.ack_num() - connection->tx_unacked - 1;
            connection->transmit_buffer.pop_front(nullptr, acknowledged_data);

            auto ack_num = seq_num + packet.size() + 1;

            connection->state = State::Established;
            connection->rx_initial_seq_num = seq_num;
            connection->rx_next_seq_num = ack_num;
            connection->tx_unacked = packet.ack_num();

            connection->receive_buffer.push_back(packet.payload(), packet.size());

            send_packet = true;

            // send ACK on SYN+ACK
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
            packet.set_flags(Flag::Ack);
            packet.set_ack_num(ack_num);

            connection->rx_acked = ack_num;

            break;
        }
        case State::SynReceived: {
            // SYN again? resend SYN+ACK in tx()
            if ((packet.flags() & Flag::Syn) == Flag::Syn) {
                break;
            }

            // else assume that the other side has received our SYN+ACK
            // but we didn't get the ACK

            connection->state = State::Established;
        }
        case State::Established: {
            if (((packet.flags() & Flag::Ack) == Flag::Ack)) {
                auto acknowledged_data = packet.ack_num() - connection->tx_unacked;
                connection->transmit_buffer.pop_front(nullptr, acknowledged_data);
                connection->tx_unacked = packet.ack_num();
            } else {
                send_packet = true;

                auto seq_num = packet.seq_num();
                auto to_ack_num = seq_num + packet.size();

                // get payload data
                connection->receive_buffer.push_back(packet.payload(), packet.size());

                auto fin = ((packet.flags() & Flag::Fin) == Flag::Fin);

                packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);

                if (fin) {
                    connection->tx_next_seq_num++;
                    to_ack_num++;

                    // send FIN+ACK on FIN
                    packet.set_flags(Flag::Fin | Flag::Ack);

                    connection->state = State::LastAck;

                    connection->close_at = Time::get_time_in_ms() + TIMEWAIT * 1000;
                    connection->tx_last_time = Time::get_time_in_ms();
                } else {
                    packet.set_flags(Flag::Ack);
                }

                packet.set_ack_num(to_ack_num);

                connection->rx_acked = to_ack_num;
                connection->rx_next_seq_num = to_ack_num;
            }

            break;
        }
        case State::FinWait: {
            if ((packet.flags() & (Flag::Fin | Flag::Ack)) != (Flag::Fin | Flag::Ack)) {
                return;
            }

            if (connection->tx_unacked >= packet.ack_num() || connection->tx_next_seq_num < packet.ack_num()) {
                debug("FIN+ACK acknowledges wrong sequence number");
            }

            auto seq_num = packet.seq_num();

            auto acknowledged_data = packet.ack_num() - connection->tx_unacked - 1;
            connection->transmit_buffer.pop_front(nullptr, acknowledged_data);

            connection->tx_unacked += acknowledged_data;

            auto ack_num = seq_num + packet.size() + 1;

            send_packet = true;

            // send ACK on FIN+ACK
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
            packet.set_flags(Flag::Ack);
            packet.set_ack_num(ack_num);

            connection->rx_acked = ack_num;
            connection->state = State::TimeWait;

            break;
        }
        case State::TimeWait: {
            send_packet = true;

            // send ACK on FIN+ACK
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
            packet.set_flags(Flag::Ack);
            packet.set_ack_num(connection->rx_acked);

            break;
        }
        case State::Closing: {
            break;
        }
        case State::CloseWait: {
            break;
        }
        case State::LastAck: {
            if ((packet.flags() & Flag::Ack) != Flag::Ack) {
                return;
            }

            connection->state = State::Closed;
            connection->rx_next_seq_num++;
            connection->tx_unacked++;

            break;
        }
        case State::TimeWait: {
            break;
        }
        default:
            error("this should not happen");
    }

    if (!send_packet) return;

    // pay and encrypt payload
    if (packet.size() > 0) {
        packet.pad_payload();
        packet.encrypt_payload(aes_key, aes_iv);
    }
    packet.update_hmac(hmac_key, sizeof(hmac_key));

    network.send(tcp_buffer, 44 + packet.size(), 10);
}

void TcpEndpoint::tx(ssize_t timeout) {
    auto tx_time = Time::get_time_in_ms();

    Connection *connection = nullptr;
    auto num_connections = connections.stored_connections();
    auto timer_expired = false;

    for (auto i = 0; i < num_connections; i++) {
        auto conn = connections.get_connection(next_tx_connection);

        next_tx_connection = (next_tx_connection + 1) % num_connections;

        if (conn->tx_data_to_send() || (timer_expired = conn->tx_timer_expired(tx_time)) || conn->to_be_closed()) {
            connection = conn;
            break;
        }
    }

    // nothing to transmit for all connections
    if (connection == nullptr) {
        return;
    }

    // create S3TP packet in transmit buffer
    auto packet = SpaceTcpPacket::create_unchecked(tcp_buffer, buffer_len);

    switch (connection->state) {
        case State::Closed: {
            if (!connection->tx_data_to_send()) {
                return;
            }

            // how much data to transmit?
            auto len = connection->transmit_buffer.used_space();
            len = (len > PAYLOAD_SIZE) ? PAYLOAD_SIZE : len;

            uint8_t data[PAYLOAD_SIZE]{0};
            connection->transmit_buffer.copy(data, len);

            // send SYN packet
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
            packet.set_flags(Flag::Syn);
            packet.set_payload(data, len);

            // update next sequence number
            connection->tx_next_seq_num += packet.size() + 1;

            connection->state = State::SynSent;

            break;
        }
        case State::Listen: {
            // do nothing if we are in a listening state

            return;
        }
        case State::SynSent: {
            if (!timer_expired) {
                return;
            }

            // how much data to transmit?
            auto len = connection->transmit_buffer.used_space();
            len = (len > PAYLOAD_SIZE) ? PAYLOAD_SIZE : len;

            uint8_t data[PAYLOAD_SIZE]{0};
            connection->transmit_buffer.copy(data, len);

            // send SYN packet
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_initial_seq_num);
            packet.set_flags(Flag::Syn);
            packet.set_payload(data, len);

            break;
        }
        case State::SynReceived: {
            if (!timer_expired) {
                return;
            }

            auto len = connection->transmit_buffer.used_space();
            len = (len > PAYLOAD_SIZE) ? PAYLOAD_SIZE : len;

            uint8_t data[PAYLOAD_SIZE]{0};
            connection->transmit_buffer.copy(data, len);

            // send SYN+ACK on SYN
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_initial_seq_num);
            packet.set_flags(Flag::Syn | Flag::Ack);
            packet.set_ack_num(connection->rx_acked);
            packet.set_payload(data, len);

            break;
        }
        case State::Established: {
            if (connection->tx_data_in_flight() >= PAYLOAD_SIZE * WINDOWSIZE) {
                // tx window full
                return;
            }

            auto len = connection->transmit_buffer.used_space() - connection->tx_data_in_flight();
            len = (len > PAYLOAD_SIZE) ? PAYLOAD_SIZE : len;

            uint8_t data[PAYLOAD_SIZE]{0};
            connection->transmit_buffer.copy(data, len, connection->tx_data_in_flight());

            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
            packet.set_payload(data, len);

            connection->tx_next_seq_num += packet.size();

            break;
        }
        case State::FinWait: {
            if (!timer_expired) {
                return;
            }

            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num - 1);
            packet.set_flags(Flag::Fin);

            break;
        }
        case State::Closing: {
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num++);
            packet.set_flags(Flag::Fin);

            connection->state = State::FinWait;

            break;
        }
        case State::CloseWait: {
            return;
        }
        case State::LastAck: {
            if (!timer_expired) {
                return;
            }

            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num - 1);
            packet.set_ack_num(connection->rx_acked);
            packet.set_flags(Flag::Fin | Flag::Ack);

            if (connection->close_at < Time::get_time_in_ms()) {
                // cool-off time exceeded, connection closed
                connection->state = State::Closed;
            }

            break;
        }
        case State::TimeWait: {
            connection->state = State::Closed;

            return;
        }
        default:
            error("this should not happen");
    }

    connection->tx_last_time = tx_time;

    // pad and encrypt payload if necessary
    if (packet.size() > 0) {
        packet.pad_payload();
        packet.encrypt_payload(aes_key, aes_iv);
    }

    packet.update_hmac(hmac_key, sizeof(hmac_key));

    network.send(tcp_buffer, 44 + packet.size(), 10);
}

auto TcpEndpoint::create_connection(uint8_t *buffer, size_t len, uint8_t rx_port, uint8_t tx_port) -> Connection * {
    return connections.create_connection(buffer, len, rx_port, tx_port, *this);
}

}  // namespace space_tcp
