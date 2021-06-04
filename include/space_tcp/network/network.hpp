#ifndef SPACE_TCP_NETWORK_HPP
#define SPACE_TCP_NETWORK_HPP

#include <unistd.h>
#include <cstdint>

namespace space_tcp {

/// Interface for the stack used below S3TP, e.g., IPv4+TUN. For RODOS, this
/// interface is yet to be implemented, e.g., Nanolink+Topics.
class NetworkInterface {
public:
    virtual ~NetworkInterface() = default;

    /// Receive up to `len` bytes into `buffer` from the underlying network.
    virtual auto receive(uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t = 0;

    /// Send out `len` bytes from `buffer` via the underlying network.
    virtual auto send(const uint8_t *buffer, size_t len, ssize_t timeout) -> ssize_t = 0;
};

}  // namespace space_tcp

#endif //SPACE_TCP_NETWORK_HPP
