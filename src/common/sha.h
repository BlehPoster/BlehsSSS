#pragma once

#include <vector>
#include <string>

namespace bleh::common {

    class Sha2 {
    public:
        static std::vector<uint8_t> sha256(const std::vector<uint8_t>& in);
    };

}