#include "space_tcp/time.hpp"

#include <chrono>

// TODO: implement for RODOS

namespace space_tcp {

auto space_tcp::Time::get_time() -> uint64_t {
    return std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
}

}  // namespace space_tcp