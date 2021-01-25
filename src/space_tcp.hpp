#ifndef SPACE_TCP_SPACE_TCP_HPP
#define SPACE_TCP_SPACE_TCP_HPP

#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "network/network.hpp"

#ifdef __linux__

#include "network/tun.hpp"

#endif

#include "protocol/protocol.hpp"

#include "endpoint.hpp"
#include "connection.hpp"

namespace space_tcp {

#ifdef __linux__

template<typename std::size_t S>
auto create_tun_interface(uint8_t (&buffer)[S]) -> TunInterface {
    return TunInterface::create(&*buffer, S);
}

#else

template<typename std::size_t S>
auto create_topic(uint8_t (&buffer)[S]) {
    // TODO
    std::cout << "guess this is rodos here" << std::endl;
}

#endif

template<typename std::size_t S, std::size_t C>
auto create_tcp_endpoint(uint8_t (&buffer)[S], NetworkInterface &network, Connections<C> &connections) -> TcpEndpoint {
    return TcpEndpoint::create(&*buffer, S, &connections, network);
}

template<typename std::size_t S>
auto create_connection(uint8_t (&buffer)[S], uint8_t rx_port, uint8_t tx_port, TcpEndpoint &endpoint) -> Connection * {
    return endpoint.create_connection(buffer, S, rx_port, tx_port);
}

} // namespace space_tcp

#endif //SPACE_TCP_SPACE_TCP_HPP
