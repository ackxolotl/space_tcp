#include <gtest/gtest.h>

#include "crypto/sha256.hpp"

TEST(Sha256DigestStringTest, Default) {
    auto sha = space_tcp::Sha256::create();
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha.digest_as_str());
}

TEST(Sha256DigestStringTest, WithInput) {
    auto sha = space_tcp::Sha256::create();
    sha.update("test");
    EXPECT_EQ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", sha.digest_as_str());
}

TEST(Sha256DigestStringTest, WithByteArrayAsInput) {
    auto sha = space_tcp::Sha256::create();
    uint8_t text[] = {'t', 'e', 's', 't'};
    sha.update(text, sizeof(text));
    EXPECT_EQ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", sha.digest_as_str());
}

TEST(Sha256DigestTest, Default) {
    auto sha = space_tcp::Sha256::create();
    auto actual = sha.digest();

    uint8_t expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                          0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                          0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

    for (auto i = 0; i < 32; i++) {
        ASSERT_EQ(expected[i], actual[i]);
    }
}

TEST(Sha256DigestTest, WithInput) {
    auto sha = space_tcp::Sha256::create();
    sha.update("test");
    auto actual = sha.digest();

    uint8_t expected[] = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5,
                          0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d,
                          0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};

    for (auto i = 0; i < 32; i++) {
        ASSERT_EQ(expected[i], actual[i]);
    }
}
