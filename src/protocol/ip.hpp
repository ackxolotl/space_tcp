#ifndef SPACE_TCP_IP_HPP
#define SPACE_TCP_IP_HPP

#include "protocol.hpp"

namespace space_tcp {

// TODO: respect endianness

class Ipv4 : public Protocol {
public:
    static auto create_unchecked(uint8_t *buffer, size_t len) -> Ipv4 {
        return {buffer, len};
    }

    auto is_valid_packet() {
        if (version() != 0x4) {
            return false;
        }

        // TODO: check checksum, ...

        return true;
    }

    auto version() -> uint8_t {
        return buffer[0] >> 4;
    }

    auto ihl() -> uint8_t {
        return buffer[0] & 0xf;
    }

    auto dscp() -> uint8_t {
        return buffer[1] >> 2;
    }

    auto ecn() -> uint8_t {
        return buffer[1] & 0x3;
    }

    auto length() -> uint16_t {
        return (buffer[2] << 8) + buffer[3];
    }

    // TODO: implement all getter

    auto payload() -> uint8_t * {
        return buffer + ihl() * 4;
    }

    auto set_version(uint8_t version) {
        buffer[0] = (version << 4) + ihl();
    }

    auto set_ihl(uint8_t ihl) {
        buffer[0] = (version() << 4) + ihl;
    }

    auto set_dscp(uint8_t dscp) {
        buffer[1] = (dscp << 2) + ecn();
    }

    auto set_ecn(uint8_t ecn) {
        buffer[1] = (dscp() << 2) + ecn;
    }

    // TODO: implement all setter

private:
    Ipv4(uint8_t *buffer, size_t len) : buffer{buffer}, len{len} {};

    uint8_t *buffer;
    size_t len;
};

} // namespace space_tcp

#endif //SPACE_TCP_IP_HPP
