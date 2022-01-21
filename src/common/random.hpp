#pragma once
#include <random>
#include <inttypes.h>
#include <limits>

namespace bleh::random {
    class random {
    public:
        static int64_t random_number_in_range(int64_t min, int64_t max) {
            std::uniform_int_distribution<int64_t> distr(min, max);
            return distr(gen);
        }
        static std::vector<uint8_t> random_bytes(uint32_t len) {
            decltype(random_bytes(len)) r;
            for (uint32_t i = 0; i < len; ++i) {
                r.push_back(static_cast<uint8_t>(random::random_number_in_range(0, std::numeric_limits<uint8_t>::max())));
            }
            return r;
        }
    private:
        static std::random_device rd;
        static std::mt19937 gen;
    };
}