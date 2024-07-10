#pragma once

#include <common/common.h>

#include <string>

namespace bleh::common {

    class Base64 {
    public:
        static auto encoded_length(size_t len) {
            return 4 * (len / 3) + 5;
        }

        static auto decoded_length(size_t len) {
            return 3 * (len / 4);
        }

        template<typename O, typename T, typename = std::enable_if_t<allowed_containers<T>::is_allowed()>>
        static O encode(const T& data) {
            return encode<T, O>(data);
        }

        template<typename T, typename O = T, typename = std::enable_if_t<allowed_containers<T>::is_allowed()>>
        static O encode(const T& data) {
            auto out = O{};
            unsigned int size = static_cast<unsigned int>(data.size());
            out.resize(encoded_length(size));
            base64_encode(reinterpret_cast<const unsigned char*>(data.data()), size, reinterpret_cast<unsigned char*>(out.data()), size);
            out.resize(size);
            return out;
        }

        static void base64_encode(const unsigned char* in, unsigned int in_size, unsigned char* out, unsigned int& out_size);

        template<typename O, typename T, typename = std::enable_if_t<allowed_containers<T>::is_allowed()>>
        static T decode(const T& data) {
            return decode<T, O>(data);
        }

        template<typename T, typename O = T, typename = std::enable_if_t<allowed_containers<T>::is_allowed()>>
        static T decode(const T& data) {
            auto out = T{};
            unsigned int size = static_cast<unsigned int>(decoded_length(data.size()));
            out.resize(size);
            base64_decode(reinterpret_cast<const unsigned char*>(data.data()), static_cast<unsigned int>(data.size()), reinterpret_cast<unsigned char*>(out.data()), size);
            out.resize(size);
            return out;
        }

        static void Base64::base64_decode(const unsigned char* in, unsigned int in_size, unsigned char* out, unsigned int& out_size);
    };

}