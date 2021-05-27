#ifndef SPACE_TCP_AES128_HPP
#define SPACE_TCP_AES128_HPP

#include <cstdint>
#include <cstddef>

namespace space_tcp {

struct aes128_ctx {
    uint8_t round_key[176]{};
    uint8_t iv[16]{};
};

class Aes128 {
public:
    static auto create() -> Aes128 {
        return {};
    }

    void init(const uint8_t key[16], const uint8_t iv[16]);

    void encrypt_cbc(uint8_t *buf, size_t len);

    void decrypt_cbc(uint8_t *buf, size_t len);

private:
    aes128_ctx ctx{};
};

}  // namespace space_tcp

#endif //SPACE_TCP_AES128_HPP
