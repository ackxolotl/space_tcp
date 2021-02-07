#ifndef SPACE_TCP_IP_HPP
#define SPACE_TCP_IP_HPP

#ifndef __rodos__

#include <arpa/inet.h>

#endif

#include "protocol.hpp"

namespace space_tcp {

class Ipv4 : public Protocol {
public:
    static auto create_unchecked(uint8_t *buffer, size_t len) -> Ipv4 {
        return {buffer, len};
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
        return ntohs((buffer[3] << 8) + buffer[2]);
    }

    auto identification() -> uint16_t {
        return ntohs((buffer[5] << 8) + buffer[4]);
    }

    auto flags() -> uint8_t {
        return buffer[6] >> 5;
    }

    auto fragment_offset() -> uint16_t {
        return ntohs((buffer[7] << 8) + (buffer[6] & 0x1f));
    }

    auto ttl() -> uint8_t {
        return buffer[8];
    }

    auto protocol() -> uint8_t {
        return buffer[9];
    }

    auto checksum() -> uint16_t {
        return ntohs((buffer[11] << 8) + buffer[10]);
    }

    auto source_ip() -> uint32_t {
        return ntohl((buffer[15] << 24) + (buffer[14] << 16) + (buffer[13] << 8) + buffer[12]);
    }

    auto dest_ip() -> uint32_t {
        return ntohl((buffer[19] << 24) + (buffer[18] << 16) + (buffer[17] << 8) + buffer[16]);
    }

    auto options() -> uint8_t * {
        return buffer + 20;
    }

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

    auto set_length(uint16_t length) {
        length = htons(length);

        buffer[2] = length;
        buffer[3] = length >> 8;
    }

    auto set_identification(uint16_t identification) {
        identification = htons(identification);

        buffer[4] = identification;
        buffer[5] = identification >> 8;
    }

    auto set_flags(uint8_t flags) {
        buffer[6] = (buffer[6] & 0x1f) + (flags << 5);
    }

    auto set_fragment_offset(uint16_t fragment_offset) {
        fragment_offset = htons(fragment_offset);

        buffer[6] = (buffer[6] & 0xe0) + (fragment_offset & 0x1f);
        buffer[7] = fragment_offset >> 8;
    }

    auto set_ttl(uint8_t ttl) {
        buffer[8] = ttl;
    }

    auto set_protocol(uint8_t protocol) {
        buffer[9] = protocol;
    }

    auto set_checksum(uint16_t checksum) {
        checksum = htons(checksum);

        buffer[10] = checksum;
        buffer[11] = checksum >> 8;
    }

    auto set_source_ip(uint32_t source_ip) {
        source_ip = htonl(source_ip);

        buffer[12] = source_ip;
        buffer[13] = source_ip >> 8;
        buffer[14] = source_ip >> 16;
        buffer[15] = source_ip >> 24;
    }

    auto dest_ip(uint32_t dest_ip) {
        dest_ip = htonl(dest_ip);

        buffer[16] = dest_ip;
        buffer[17] = dest_ip >> 8;
        buffer[18] = dest_ip >> 16;
        buffer[19] = dest_ip >> 24;
    }

    auto set_payload(uint8_t *payload, size_t length) {
        if (ihl() * 4 + length > len) {
            // too long for this packet buffer, throw exception?
        }

        auto data = buffer + ihl() * 4;
        for (; length > 0; data++, payload++, length--) {
            *data = *payload;
        }
    }

    auto is_valid_packet() {
        if (version() != 0x4) {
            return false;
        }

        // header truncated?
        if (ihl() * 4 > len) {
            return false;
        }

        // payload truncated?
        if (length() > len) {
            return false;
        }

        // checksum valid?
        if (!calculate_checksum() != 0) {
            return false;
        }

        return true;
    }

    auto calculate_checksum() -> uint16_t {
        uint16_t header_len = ihl() * 4;
        uint8_t *data = buffer;
        uint32_t acc = 0;

        for (; header_len > 1; header_len -= 2, data += 2) {
            acc += ((*data) << 8) + *(data + 1);
        }

        if (header_len > 0) {
            acc += (*data) << 8;
        }

        acc = (acc >> 16) + (acc & 0x0000ffffUL);
        if ((acc & 0xffff0000UL) != 0) {
            acc = (acc >> 16) + (acc & 0x0000ffffUL);
        }

        return ntohs(acc);
    }

    auto update_checksum() {
        set_checksum(0);
        auto checksum = calculate_checksum();
        set_checksum(checksum);
    }

private:
    Ipv4(uint8_t *buffer, size_t len) : buffer{buffer}, len{len} {};

    uint8_t *buffer;
    size_t len;
};

} // namespace space_tcp

#endif //SPACE_TCP_IP_HPP
