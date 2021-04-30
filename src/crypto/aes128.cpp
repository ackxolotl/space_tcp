#include "aes128.hpp"
#include "aes.hpp"

namespace space_tcp {

void Aes128::init(const uint8_t key[16], const uint8_t iv[16]) {
    AES_init_ctx_iv(reinterpret_cast<AES_ctx *>(&ctx), key, iv);
}

void Aes128::encrypt_cbc(uint8_t *buf, size_t len) {
    AES_CBC_encrypt_buffer(reinterpret_cast<AES_ctx *>(&ctx), buf, len);
}

void Aes128::decrypt_cbc(uint8_t *buf, size_t len) {
    AES_CBC_decrypt_buffer(reinterpret_cast<AES_ctx *>(&ctx), buf, len);
}

}  // namespace space_tcp