#ifndef SPACE_TCP_PROTOCOL_HPP
#define SPACE_TCP_PROTOCOL_HPP

namespace space_tcp {

/// Abstract class for protocol implementations.
class Protocol {
public:
    virtual ~Protocol() = default;
};

}  // namespace space_tcp

#endif //SPACE_TCP_PROTOCOL_HPP
