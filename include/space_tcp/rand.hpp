#ifndef SPACE_TCP_RAND_HPP
#define SPACE_TCP_RAND_HPP

#include <cstdint>

namespace space_tcp {

/// Class with functions to generate random numbers.
class Rng {
public:
    /// Generates a random number in range [from, to].
    static auto generate_random_number(uint16_t from, uint16_t to) -> uint16_t;
};

}  // namespace space_tcp

#endif //SPACE_TCP_RAND_HPP
