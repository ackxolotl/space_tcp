#ifndef SPACE_TCP_SPACE_TCP_PACKET_HPP
#define SPACE_TCP_SPACE_TCP_PACKET_HPP

#ifndef __rodos__

#include <arpa/inet.h>

#endif

#include "crypto/aes128.hpp"
#include "crypto/hmac.hpp"
#include "space_tcp/log.hpp"
#include "protocol.hpp"

namespace space_tcp {

enum class Flag {
    NoFlags = 0x0,
    Syn = 0x1,
    Ack = 0x2,
    Rst = 0x4,
    Fin = 0x8,
};

inline auto operator|(Flag a, Flag b) -> Flag {
    return static_cast<Flag>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

inline auto operator&(Flag a, Flag b) -> Flag {
    return static_cast<Flag>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}

class SpaceTcpPacket : public Protocol {
public:
    static auto create_unchecked(uint8_t *buffer, size_t len) -> SpaceTcpPacket {
        return {buffer, len};
    }

    auto version() -> uint8_t {
        return buffer[0] >> 4;
    }

    auto msg_type() -> uint8_t {
        return static_cast<uint8_t>(buffer[0] & 0xf);
    }

    auto flags() -> Flag {
        return static_cast<Flag>(buffer[1]);
    }

    auto src_port() -> uint16_t {
        return ntohs((buffer[3] << 8) + buffer[2]);
    }

    auto dst_port() -> uint16_t {
        return ntohs((buffer[5] << 8) + buffer[4]);
    }

    auto sequence_number() -> uint16_t {
        return ntohs((buffer[7] << 8) + buffer[6]);
    }

    auto acknowledgment_number() -> uint16_t {
        return ntohs((buffer[9] << 8) + buffer[8]);
    }

    auto size() -> uint16_t {
        return ntohs((buffer[11] << 8) + buffer[10]);
    }

    auto hmac() -> uint8_t * {
        return buffer + 12;
    }

    auto payload() -> uint8_t * {
        return buffer + 44;
    }

    auto set_version(uint8_t version) {
        buffer[0] = (version << 4) + msg_type();
    }

    auto set_msg_type(uint8_t msg_type) {
        buffer[0] = (version() << 4) + msg_type;
    }

    auto set_flags(Flag flags) {
        buffer[1] = static_cast<uint8_t>(flags);
    }

    auto set_src_port(uint16_t src_port) {
        src_port = htons(src_port);

        buffer[2] = static_cast<uint8_t>(src_port);
        buffer[3] = static_cast<uint8_t>(src_port >> 8);
    }

    auto set_dst_port(uint16_t dst_port) {
        dst_port = htons(dst_port);

        buffer[4] = static_cast<uint8_t>(dst_port);
        buffer[5] = static_cast<uint8_t>(dst_port >> 8);
    }

    auto set_sequence_number(uint16_t sequence_number) {
        sequence_number = htons(sequence_number);

        buffer[6] = static_cast<uint8_t>(sequence_number);
        buffer[7] = static_cast<uint8_t>(sequence_number >> 8);
    }

    auto set_acknowledgment_number(uint16_t acknowledgment_number) {
        acknowledgment_number = htons(acknowledgment_number);

        buffer[8] = static_cast<uint8_t>(acknowledgment_number);
        buffer[9] = static_cast<uint8_t>(acknowledgment_number >> 8);
    }

    auto set_size(uint16_t size) {
        size = htons(size);

        buffer[10] = static_cast<uint8_t>(size);
        buffer[11] = static_cast<uint8_t>(size >> 8);
    }

    auto set_hmac(const uint8_t hash[32]) {
        auto data = buffer + 12;

        for (auto i = 0; i < 32; i++) {
            data[i] = hash[i];
        }
    }

    auto set_payload(const uint8_t *payload, size_t len) {
        if (44 + len > this->len) {
            warn("payload exceeds buffer size and will be truncated");
            len = this->len - 44;
        }

        set_size(static_cast<uint16_t>(len));

        auto data = this->payload();
        for (; len > 0; data++, payload++, len--) {
            *data = *payload;
        }
    }

    auto pad_payload() {
        auto offset = size();
        auto pad = static_cast<uint8_t>(16 - (offset % 16));

        if (offset + pad + 44 > len) {
            warn("padded payload exceeds buffer size, payload will be truncated");
            offset = static_cast<uint16_t>(len - 44 - pad);
        }

        for (auto i = 0; i < pad; i++) {
            payload()[offset + i] = pad;
        }

        set_size(offset + pad);
    }

    auto depad_payload() {
        auto offset = size();
        uint8_t pad = payload()[offset - 1];

        for (auto i = 0; i < pad; i++) {
            payload()[offset - 1 - i] = 0x00;
        }

        set_size(offset - pad);
    }

    auto encrypt_payload(const uint8_t *key, uint8_t *iv) {
        auto aes = space_tcp::Aes128::create();
        auto seq = sequence_number();

        // message IV depends on sequence number
        iv[0] ^= seq >> 8;
        iv[1] ^= seq;

        aes.init(key, iv);

        // reset IV to previous value
        iv[0] ^= seq >> 8;
        iv[1] ^= seq;

        aes.encrypt_cbc(payload(), size());
    }

    auto decrypt_payload(const uint8_t *key, uint8_t *iv) {
        auto aes = space_tcp::Aes128::create();
        auto seq = sequence_number();

        // message IV depends on sequence number
        iv[0] ^= seq >> 8;
        iv[1] ^= seq;

        aes.init(key, iv);

        // reset IV to previous value
        iv[0] ^= seq >> 8;
        iv[1] ^= seq;

        aes.decrypt_cbc(payload(), size());
    }

    auto is_valid_packet(const uint8_t *key, size_t len) {
        if (version() != 0x1) {
            warn("S3TP packet with invalid version number");
            return false;
        }

        if (44 > this->len) {
            warn("S3TP packet with truncated header");
            return false;
        }

        if (44 + size() > this->len) {
            warn("S3TP packet with truncated payload");
            return false;
        }

        if (!verify_hmac(key, len)) {
            warn("S3TP packet with invalid HMAC");
            return false;
        }

        return true;
    }

    auto zero_hmac() {
        uint8_t tmp[32]{};
        set_hmac(tmp);
    }

    auto update_hmac(const uint8_t *key, size_t len) {
        zero_hmac();

        auto hmac = space_tcp::Hmac::create(key, len);
        hmac.sha256_finalize(this->buffer, 44 + size());

        set_hmac(hmac.get_digest());
    }

    auto verify_hmac(const uint8_t *key, size_t len) -> bool {
        uint8_t hash[32];

        for (auto i = 0; i < 32; i++) {
            hash[i] = hmac()[i];
        }

        zero_hmac();

        auto hmac = space_tcp::Hmac::create(key, len);
        hmac.sha256_finalize(this->buffer, 44 + size());

        set_hmac(hash);

        for (auto i = 0; i < 32; i++) {
            if (hash[i] != hmac.get_digest()[i]) {
                return false;
            }
        }

        return true;
    }

    auto initialize() {
        set_version(0x1);
        set_msg_type(0x1);
        set_flags(Flag::NoFlags); // no flags set by default
        set_acknowledgment_number(0); // no acknowledgment number set by default
        set_size(0); // no payload yet
    }

    void print() {
        std::cout << "Version:         " << +version() << std::endl;
        std::cout << "Msg Type:        " << +msg_type() << std::endl;
        std::cout << "Flags:           " << +static_cast<uint8_t>(flags()) << std::endl;
        std::cout << "Source Port:     " << std::dec << +src_port() << std::endl;
        std::cout << "Destination Port:" << std::dec << +dst_port() << std::endl;
        std::cout << "Sequence Number: " << std::dec << +sequence_number() << std::endl;
        std::cout << "Size:            " << std::dec << +size() << std::endl;
    }

private:
    SpaceTcpPacket(uint8_t *buffer, size_t len) : buffer{buffer}, len{len} {};

    uint8_t *buffer;
    size_t len;
};

}  // namespace space_tcp

#endif //SPACE_TCP_SPACE_TCP_PACKET_HPP
