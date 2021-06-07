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
        // send RST since received S3TP does not belong to any connection

        packet.initialize(dst_port, src_port, connection->tx_next_seq_num);
        packet.set_flags(Flag::Rst);
        packet.update_hmac(hmac_key, sizeof(hmac_key));

        network.send(tcp_buffer, 44 + packet.size(), 10);

        return;
    }

    auto send_packet = false;

    switch (connection->state) {
        case State::Closed: {
            send_packet = true;

            // send RST on packets for closed connection
            packet.initialize(dst_port, src_port, connection->tx_next_seq_num);
            packet.set_flags(Flag::Rst);

            break;
        }
        case State::Listen: {
            if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
                return;
            }

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
            if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
                return;
            }

            if ((packet.flags() & (Flag::Syn | Flag::Ack)) != (Flag::Syn | Flag::Ack)) {
                return;
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
            if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
                return;
            }

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
                // new ACK?
                if (packet.ack_num() > connection->tx_unacked) {
                    auto acknowledged_data = packet.ack_num() - connection->tx_unacked;
                    connection->transmit_buffer.pop_front(nullptr, acknowledged_data);
                    connection->tx_unacked = packet.ack_num();
                }
            } else {
                send_packet = true;

                auto seq_num = packet.seq_num();
                auto to_ack_num = seq_num + packet.size();

                if (connection->rx_next_seq_num && seq_num < connection->rx_next_seq_num) {
                    // received earlier segment, acknowledge last received one

                    packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
                    packet.set_flags(Flag::Ack);
                    packet.set_ack_num(connection->rx_acked);
                } else if (connection->rx_next_seq_num && seq_num == connection->rx_next_seq_num) {
                    // next expected segment

                    // get payload data
                    connection->receive_buffer.push_back(packet.payload(), packet.size());

                    auto fin = ((packet.flags() & Flag::Fin) == Flag::Fin);

                    packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);

                    if (fin) {
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
                } else {
                    packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num);
                    packet.set_flags(Flag::Ack);
                    packet.set_ack_num(connection->rx_acked);
                }
            }

            break;
        }
        case State::FinWait: {
            if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
                return;
            }

            if ((packet.flags() & (Flag::Fin | Flag::Ack)) != (Flag::Fin | Flag::Ack)) {
                if ((packet.flags() & (Flag::Ack)) != (Flag::Ack)) {
                    // new ACK?
                    if (packet.ack_num() > connection->tx_unacked) {
                        auto acknowledged_data = packet.ack_num() - connection->tx_unacked;
                        connection->transmit_buffer.pop_front(nullptr, acknowledged_data);
                        connection->tx_unacked = packet.ack_num();
                    }
                }

                return;
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
            if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
                return;
            }

            if ((packet.flags() & (Flag::Fin | Flag::Ack)) != (Flag::Fin | Flag::Ack)) {
                return;
            }

            send_packet = true;

            // send ACK on FIN+ACK
            packet.initialize(connection->src_port, connection->dst_port, connection->tx_next_seq_num + 1);
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
            if (connection->rx_next_seq_num && packet.seq_num() < connection->rx_next_seq_num) {
                return;
            }

            if ((packet.flags() & Flag::Ack) != Flag::Ack) {
                return;
            }

            connection->state = State::Closed;
            connection->rx_next_seq_num++;
            connection->tx_unacked++;

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

        timer_expired = conn->tx_timer_expired(tx_time);

        if (conn->tx_data_to_send() || timer_expired || conn->to_be_closed()) {
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
            // timer expired? restart at last unacked byte
            if (timer_expired) {
                connection->tx_next_seq_num = connection->tx_unacked;
            }

            if (connection->tx_data_in_flight() >= PAYLOAD_SIZE * WINDOWSIZE) {
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

            connection->close_at = Time::get_time_in_ms() + TIMEWAIT * 1000;

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
            if (connection->close_at < Time::get_time_in_ms()) {
                // cool-off time exceeded, connection closed
                connection->state = State::Closed;
            }

            connection->tx_last_time = Time::get_time_in_ms();

            return;
        }
        default:
            error("this should not happen");
    }

    connection->tx_last_time = tx_time;

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
