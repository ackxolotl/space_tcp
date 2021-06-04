#include "space_tcp/time.hpp"

#include <chrono>

namespace space_tcp {

auto space_tcp::Time::get_time_in_ms() -> uint64_t {
    return std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
}

}  // namespace space_tcp