#include <gtest/gtest.h>

#include "crypto/hmac.hpp"

TEST(HmacTest, Test0) {
    uint8_t key[64] = {'a'};
    uint8_t block[1024] = {'a'};

    auto hmac = space_tcp::Hmac::create(key, 64);
    hmac.sha256_finalize(block, 1);

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << +hmac.get_digest()[i];
    }

    EXPECT_EQ("3ecf5388e220da9e0f919485deb676d8bee3aec046a779353b463418511ee622", s.str());
}

TEST(HmacTest, Test1) {
    uint8_t key[64] = {'a'};
    uint8_t block[1024] = {'a'};

    auto sha = space_tcp::Sha256::create();
    sha.finalize(key, 64);

    auto hmac = space_tcp::Hmac::create(sha.get_hash(), 64);
    hmac.sha256_finalize(block, 1);

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << +hmac.get_digest()[i];
    }

    EXPECT_EQ("73081bcdc868d4f9edb74169c5db1030ec0814f71de097f4a465314a095b5a3c", s.str());
}

TEST(HmacTest, Test2) {
    uint8_t key[64] = {'b', 'c'};
    uint8_t block[1024] = {'q', 'x'};

    auto hmac = space_tcp::Hmac::create(key, 64);
    hmac.sha256_finalize(block, 2);

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << +hmac.get_digest()[i];
    }

    EXPECT_EQ("7574a36b8243271d1a88c16a0ad7fc4c76fb64296c9e4f802193deac587bb593", s.str());
}

TEST(HmacTest, Test3) {
    uint8_t key[64] = {'b', 'c'};
    uint8_t block[1024] = {'q', 'x'};

    auto sha = space_tcp::Sha256::create();
    sha.finalize(key, 64);

    auto hmac = space_tcp::Hmac::create(sha.get_hash(), 64);
    hmac.sha256_finalize(block, 2);

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << +hmac.get_digest()[i];
    }

    EXPECT_EQ("0db7faa99c68647680a65187193e433e5f8722e146cce2994b39d6b87f91b1d0", s.str());
}

TEST(HmacTest, Test4) {
    uint8_t key[64] = {'a', 'a', 'z', 'z'};
    uint8_t block[1024] = {'x', 'x', 'x'};

    auto sha = space_tcp::Sha256::create();
    sha.finalize(key, 64);

    auto hmac = space_tcp::Hmac::create(sha.get_hash(), 64);
    hmac.sha256_finalize(block, 3);

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << +hmac.get_digest()[i];
    }

    EXPECT_EQ("d900b22adb27f8f0a31b2a8d7d47f699949f9bd5fea58d705a0c666de0b3a852", s.str());
}