#include "space_tcp/rand.hpp"

#include <random>


// TODO: implement for RODOS

namespace space_tcp {

auto Rng::generate_random_number(uint16_t from, uint16_t to) -> uint16_t {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(from, to);

    return distrib(gen);
}

}  // namespace space_tcp