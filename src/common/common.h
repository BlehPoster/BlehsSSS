#pragma once

#include <string>
#include <vector>
#include <array>

namespace bleh::common {

    template<typename T>
    struct allowed_containers : public std::integral_constant<bool, 
        std::is_same_v<T, std::vector<uint8_t>> ||
        std::is_same_v<T, std::string>
    > {};

    template<typename T>
    static constexpr auto allowed_containers_v = allowed_containers<T>{};

}