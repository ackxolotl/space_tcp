#ifndef SPACE_TCP_NETWORK_HPP
#define SPACE_TCP_NETWORK_HPP

namespace space_tcp {

class NetworkInterface {
public:
    virtual ~NetworkInterface() = default;

    virtual auto receive(uint8_t *buffer, size_t len, size_t timeout) -> ssize_t = 0;

    virtual auto send(const uint8_t *buffer, size_t len, size_t timeout) -> ssize_t = 0;
};

} // namespace space_tcp

#endif //SPACE_TCP_NETWORK_HPP
