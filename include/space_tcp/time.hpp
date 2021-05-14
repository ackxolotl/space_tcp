#ifndef SPACE_TCP_TIME_HPP
#define SPACE_TCP_TIME_HPP

#include <cstdint>

namespace space_tcp {

/// Class with time-related functions.
class Time {
public:
    /// Returns milliseconds since the Unix epoch.
    static auto get_time() -> uint64_t;
};

}  // namespace space_tcp

#endif //SPACE_TCP_TIME_HPP
