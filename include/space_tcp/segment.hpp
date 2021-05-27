#ifndef SPACE_TCP_SEGMENT_HPP
#define SPACE_TCP_SEGMENT_HPP

namespace space_tcp {

struct segment {
    size_t offset;
    size_t len;
};

template<typename std::size_t S>
class Segments {
public:
    auto insert(size_t offset, size_t len) -> bool {
        if (stored_segments < S) {
            for (auto i = 0; i < S; i++) {
                if (segments[i].offset != 0) {
                    continue;
                }

                segments[i].offset = offset;
                segments[i].len = len;

                if (stored_segments == 0 || offset < segments[smallest_offset_index].offset) {
                    smallest_offset_index = i;
                }

                stored_segments++;

                return true;
            }
        }

        return false;
    }

    auto remove(size_t offset, size_t len) -> bool {
        if (stored_segments > 0) {
            for (auto i = 0; i < S; i++) {
                if (segments[i].offset != offset || segments[i].len != len) {
                    continue;
                }

                auto smallest_offset = segments[smallest_offset_index].offset;

                segments[i].offset = 0;
                segments[i].len = 0;

                if (offset == smallest_offset) {
                    update_smallest_offset();
                }

                stored_segments--;

                return true;
            }
        }

        return false;
    }

    auto contains_segments() -> bool {
        return (stored_segments > 0);
    }

    auto get_smallest_offset_segment() -> segment {
        return segments[smallest_offset_index];
    }

private:
    auto update_smallest_offset() {
        auto smallest_offset = -1;
        for (auto i = 0; i < S; i++) {
            if (segments[i].offset > 0 && segments[i].offset < smallest_offset) {
                smallest_offset = segments[i].offset;
                smallest_offset_index = i;
            }
        }
    }

    segment segments[S]{};
    size_t stored_segments{};
    size_t smallest_offset_index{};
};

}  // namespace space_tcp

#endif //SPACE_TCP_SEGMENT_HPP
