#pragma once

#include <string>
#include <vector>

namespace bleh::common {

    template<typename T, bool v =
        std::is_same_v<T, std::vector<uint8_t>> ||
        std::is_same_v<T, std::string>
    >
    struct allowed_containers
    {
        static constexpr auto is_allowed() { return v; }
    };

}