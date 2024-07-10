#pragma once

#include <common/common.h>

#include <vector>
#include <string>
#include <assert.h>

namespace bleh::common {

    class Sha2 {
    public:
        Sha2() = delete;

        template<typename O, typename T, typename = std::enable_if_t<allowed_containers<T>::is_allowed()>>
        static T sha256(const T& in) {
            return sha256<T, O>(in);
        }

        template<typename T, typename O = T, typename = std::enable_if_t<allowed_containers<T>::is_allowed()>>
        static T sha256(const T& in) {
            static constexpr const auto sha256_size = 32;

            auto out = T{};
            out.resize(sha256_size);
            unsigned int out_size = 0;
            sha256(reinterpret_cast<const uint8_t*>(in.data()), static_cast<unsigned int>(in.size()), reinterpret_cast<uint8_t*>(out.data()), out_size);
            assert(out_size == sha256_size);
            return out;
        }

        static void sha256(const unsigned char* in, unsigned int in_size, unsigned char* out, unsigned int& out_size);
    };

}