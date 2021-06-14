#include <gtest/gtest.h>

#include "crypto/hmac.hpp"

TEST(Sha256Test, Test0) {
    uint8_t message[1]{};

    auto sha = space_tcp::Sha256::create();
    sha.finalize(message, sizeof(message));

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << static_cast<unsigned int>(sha.get_hash()[i]);
    }

    EXPECT_EQ("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", s.str());
}

TEST(Sha256Test, Test1) {
    uint8_t message[] = {'t', 'e', 's', 't'};

    auto sha = space_tcp::Sha256::create();
    sha.finalize(message, sizeof(message));

    std::stringstream s;
    s << std::setfill('0') << std::hex;
    for (auto i = 0; i < 32; i++) {
        s << std::setw(2) << static_cast<unsigned int>(sha.get_hash()[i]);
    }

    EXPECT_EQ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", s.str());
}
