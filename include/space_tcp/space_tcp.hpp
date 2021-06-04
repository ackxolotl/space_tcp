#ifndef SPACE_TCP_HPP
#define SPACE_TCP_HPP

#include "network/tun.hpp"
#include "endpoint.hpp"

#include <cstdint>

#ifndef __rodos__

#include <cstdlib>
#include <iostream>

#endif

namespace space_tcp {

#ifndef __rodos__

/// Creates a TUN interface.
template<typename std::size_t S>
auto create_tun_interface(uint8_t (&buffer)[S], const tun_config &config = {}) -> TunInterface {
    return TunInterface::create(&*buffer, S, config);
}

#else

template<typename std::size_t S>
auto create_topic_socket(uint8_t (&buffer)[S]) {
    // TODO(hal): RODOS
}

#endif

/// Creates a S3TP endpoint.
template<typename std::size_t S, std::size_t C>
auto create_tcp_endpoint(uint8_t (&buffer)[S], NetworkInterface &network, Connections<C> &connections) -> TcpEndpoint {
    return TcpEndpoint::create(&*buffer, S, connections, network);
}

/// Creates a connection for a S3TP endpoint.
template<typename std::size_t S>
auto create_connection(uint8_t (&buffer)[S], uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) -> Connection * {
    return endpoint.create_connection(buffer, S, rx_port, tx_port);
}

}  // namespace space_tcp

#endif //SPACE_TCP_HPP