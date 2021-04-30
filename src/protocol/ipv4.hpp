#ifndef SPACE_TCP_IP_PACKET_HPP
#define SPACE_TCP_IP_PACKET_HPP

#include <arpa/inet.h>

#include "space_tcp/log.hpp"
#include "protocol.hpp"

namespace space_tcp {

class Ipv4Packet : public Protocol {
public:
    static auto create_unchecked(uint8_t *buffer, size_t len) -> Ipv4Packet {
        return {buffer, len};
    }

    auto version() -> uint8_t {
        return buffer[0] >> 4;
    }

    auto ihl() -> uint8_t {
        return static_cast<uint8_t>(buffer[0] & 0xf);
    }

    auto dscp() -> uint8_t {
        return buffer[1] >> 2;
    }

    auto ecn() -> uint8_t {
        return static_cast<uint8_t>(buffer[1] & 0x3);
    }

    auto length() -> uint16_t {
        return ntohs(buffer[2] + (buffer[3] << 8));
    }

    auto identification() -> uint16_t {
        return ntohs(buffer[4] + (buffer[5] << 8));
    }

    auto flags() -> uint8_t {
        return buffer[6] >> 5;
    }

    auto fragment_offset() -> uint16_t {
        return ntohs(static_cast<uint16_t>((buffer[6] & 0x1f) + (buffer[7] << 8)));
    }

    auto ttl() -> uint8_t {
        return buffer[8];
    }

    auto protocol() -> uint8_t {
        return buffer[9];
    }

    auto checksum() -> uint16_t {
        return ntohs(buffer[10] + (buffer[11] << 8));
    }

    auto src_ip() -> uint32_t {
        return ntohl(buffer[12] + (buffer[13] << 8) + (buffer[14] << 16) + (buffer[15] << 24));
    }

    auto dst_ip() -> uint32_t {
        return ntohl(buffer[16] + (buffer[17] << 8) + (buffer[18] << 16) + (buffer[19] << 24));
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

        buffer[2] = static_cast<uint8_t>(length);
        buffer[3] = static_cast<uint8_t>(length >> 8);
    }

    auto set_identification(uint16_t identification) {
        identification = htons(identification);

        buffer[4] = static_cast<uint8_t>(identification);
        buffer[5] = static_cast<uint8_t>(identification >> 8);
    }

    auto set_flags(uint8_t flags) {
        buffer[6] = static_cast<uint8_t>((buffer[6] & 0x1f) + (flags << 5));
    }

    auto set_fragment_offset(uint16_t fragment_offset) {
        fragment_offset = htons(fragment_offset);

        buffer[6] = static_cast<uint8_t>((buffer[6] & 0xe0) + (fragment_offset & 0x1f));
        buffer[7] = static_cast<uint8_t>(fragment_offset >> 8);
    }

    auto set_ttl(uint8_t ttl) {
        buffer[8] = ttl;
    }

    auto set_protocol(uint8_t protocol) {
        buffer[9] = protocol;
    }

    auto set_checksum(uint16_t checksum) {
        checksum = htons(checksum);

        buffer[10] = static_cast<uint8_t>(checksum);
        buffer[11] = static_cast<uint8_t>(checksum >> 8);
    }

    auto set_src_ip(uint32_t src_ip) {
        src_ip = htonl(src_ip);

        buffer[12] = static_cast<uint8_t>(src_ip);
        buffer[13] = static_cast<uint8_t>(src_ip >> 8);
        buffer[14] = static_cast<uint8_t>(src_ip >> 16);
        buffer[15] = static_cast<uint8_t>(src_ip >> 24);
    }

    auto set_dst_ip(uint32_t dst_ip) {
        dst_ip = htonl(dst_ip);

        buffer[16] = static_cast<uint8_t>(dst_ip);
        buffer[17] = static_cast<uint8_t>(dst_ip >> 8);
        buffer[18] = static_cast<uint8_t>(dst_ip >> 16);
        buffer[19] = static_cast<uint8_t>(dst_ip >> 24);
    }

    auto set_payload(const uint8_t *payload, size_t length) {
        if (length + ihl() * 4 > len) {
            warn("payload exceeds buffer size and will be truncated");
            length = len - ihl() * 4;
        }

        set_length(length + ihl() * 4);

        auto data = buffer + ihl() * 4;
        for (; length > 0; data++, payload++, length--) {
            *data = *payload;
        }
    }

    auto is_valid_packet() {
        if (version() != 0x4) {
            warn("IP packet with invalid version number");
            return false;
        }

        if (ihl() * 4 > len) {
            warn("IPv4 packet with truncated header");
            return false;
        }

        if (length() > len) {
            warn("IPv4 packet with truncated payload");
            return false;
        }

        if (calculate_checksum() != 0) {
            warn("IPv4 packet with invalid checksum");
            return false;
        }

        return true;
    }

    auto calculate_checksum() -> uint16_t {
        uint8_t *data = buffer;
        auto counter = ihl() * 4;
        uint32_t sum = 0;

        for (; counter > 1; data += 2, counter -= 2) {
            sum += *data << 8 | *(data + 1);
        }

        if (counter) {
            sum += *data << 8;
        }

        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        return static_cast<uint16_t>(static_cast<uint16_t>(sum) ^ 0xffff);
    }

    auto update_checksum() {
        set_checksum(0);
        auto checksums = calculate_checksum();
        set_checksum(checksums);
    }

    auto initialize() {
        set_version(0x4);
        set_ihl(0x5);
        set_dscp(0);
        set_ecn(0);
        set_length(20);
        set_flags(0x2); // don't fragment
        set_fragment_offset(0);
        set_ttl(0x40);
        set_protocol(0x99); // use an unassigned IPv4 protocol number for S3TP
    }

    void print() {
        std::cout << "Version:         " << +version() << std::endl;
        std::cout << "IHL:             " << +ihl() << std::endl;
        std::cout << "DSCP:            " << +dscp() << std::endl;
        std::cout << "ECN:             " << +ecn() << std::endl;
        std::cout << "Total length:    " << +length() << std::endl;
        std::cout << "Identification:  " << std::hex << "0x" << +identification() << std::endl;
        std::cout << "Flags:           " << std::hex << "0x" << +flags() << std::endl;
        std::cout << "Fragment offset: " << std::hex << "0x" << +fragment_offset() << std::endl;
        std::cout << "TTL:             " << std::hex << "0x" << +ttl() << std::endl;
        std::cout << "Checksum:        " << std::hex << "0x" << +checksum() << std::endl;
        std::cout << "Protocol:        " << std::hex << "0x" << +protocol() << std::endl;
        std::cout << "Source IP:       " << std::hex << "0x" << +src_ip() << std::endl;
        std::cout << "Destination IP:  " << std::hex << "0x" << +dst_ip() << std::endl;
    }

private:
    Ipv4Packet(uint8_t *buffer, size_t len) : buffer{buffer}, len{len} {};

    uint8_t *buffer;
    size_t len;
};

}  // namespace space_tcp

#endif //SPACE_TCP_IP_PACKET_HPP
