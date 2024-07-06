#pragma once

#include <string>

namespace bleh::common {

    class Base64 {
    public:
        static std::string encode(const std::string&);
        static std::string decode(const std::string&);
    };

}