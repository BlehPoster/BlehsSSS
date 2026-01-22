#include "sss.h"

#include <common/random.hpp>
#include <common/base64.h>

#include <numeric>
#include <unordered_map>
#include <sstream>
#include <limits>

namespace bleh::sss {

    std::vector<std::pair<int32_t, int64_t>> create_shares(int32_t shares, int32_t min_required_shares, int64_t secret) {
        static const constexpr auto min = std::numeric_limits<int32_t>::min();
        static const constexpr auto max = std::numeric_limits<int32_t>::max();

        decltype(create_shares(shares, min_required_shares, secret)) result;
        std::vector<int64_t> t;
        t.push_back(secret);
        for (int i = 0; i < min_required_shares - 1; ++i) {
            auto prng = random::random::random_number_in_range(min, max);
            t.push_back(prng);
        }

        for (int x = 1; x <= shares; ++x) {
            int64_t y = 0;
            int64_t b = 1;
            for (auto&& e : t) {
                y = y + (e * b);
                b *= x;
            }
            result.push_back({ x, y });
        }
        return result;
    }

    int64_t gcd(int64_t a, int64_t b)
    {
        int64_t temp;
        while (b != 0)
        {
            temp = a % b;

            a = b;
            b = temp;
        }
        return a;
    }

    void addition(int64_t& x1, int64_t& y1, int64_t x2, int64_t y2) {
        x1 = x1 * y2 + y1 * x2;
        y1 *= y2;
        auto gcd_ = gcd(x1, y1);
        x1 /= gcd_;
        y1 /= gcd_;
    }

    void multiply(int64_t& x1, int64_t& y1, int64_t x2, int64_t y2) {
        x1 *= x2;
        y1 *= y2;
        auto gcd_ = gcd(x1, y1);
        x1 /= gcd_;
        y1 /= gcd_;
    }

    int64_t reconstruct_from_shares(const std::vector<std::pair<int32_t, int64_t>>& shares, int32_t min) {
        auto x = std::vector<int64_t>();
        auto y = std::vector<int64_t>();

        for (auto&& e : shares) {
            x.push_back(e.first);
            y.push_back(e.second);
        }

        int64_t n = 0;
        int64_t d = 1;

        for (int i = 0; i < min; ++i) {
            int64_t yn = y[i];
            int64_t yd = 1;
            for (int o = 0; o < min; ++o) {
                if (i != o) {
                    int64_t xn = -x[o];
                    int64_t xd = x[i] - x[o];
                    multiply(yn, yd, xn, xd);
                }
            }
            addition(n, d, yn, yd);
        }
        return n;
    }

    std::vector<std::string> Share_Collector::stringify() const {
        std::vector<std::string> r;

        for (const auto& [index, values] : data) {
            std::stringstream ss;
            ss << "01:" << index << ":" << min << ":";

            std::vector<uint8_t> bytes;
            bytes.reserve(values.size() * sizeof(int64_t));

            for (int64_t v : values) {
                for (int i = 0; i < 8; ++i)
                    bytes.push_back((v >> (i * 8)) & 0xFF);
            }

            unsigned int out_len = bleh::common::Base64::encoded_length(bytes.size());
            std::string encoded(out_len, '\0');

            bleh::common::Base64::base64_encode(
                bytes.data(),
                bytes.size(),
                reinterpret_cast<unsigned char*>(encoded.data()),
                out_len
            );

            encoded.resize(out_len);
            ss << encoded;

            r.push_back(ss.str());
        }
        return r;
    }

    Share_Collector Share_Collector::from_strings(const std::vector<std::string>& strings) {
        DataType result;
        int32_t min = -1;

        for (const auto& str : strings) {
            std::vector<std::string> parts;
            {
                std::stringstream ss(str);
                std::string item;
                while (std::getline(ss, item, ':')) {
                    parts.push_back(item);
                }
            }

            if (parts.size() != 4) {
                return { {}, 0 };
            }

            if (parts[0] != "01") {
                return { {}, 0 };
            }

            int32_t share_index = 0;
            int32_t local_min = 0;
            try {
                share_index = std::stoi(parts[1]);
                local_min = std::stoi(parts[2]);
            }
            catch (...) {
                return { {}, 0 };
            }

            if (min == -1) {
                min = local_min;
            }
            else if (min != local_min) {
                return { {}, 0 };
            }

            std::string& encoded = parts[3];
            std::vector<uint8_t> decoded(bleh::common::Base64::decoded_length(encoded.size()));

            unsigned int decoded_len = decoded.size();
            bleh::common::Base64::base64_decode(reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size(), decoded.data(), decoded_len);

            if (decoded_len % sizeof(int64_t) != 0) {
                return { {}, 0 };
            }

            std::vector<int64_t> values;
            values.reserve(decoded_len / sizeof(int64_t));

            for (size_t i = 0; i < decoded_len; i += 8) {
                int64_t v = 0;
                for (int b = 0; b < 8; ++b) {
                    v |= static_cast<int64_t>(decoded[i + b]) << (b * 8);
                }
                values.push_back(v);
            }

            result[share_index] = std::move(values);
        }

        return { result, min };
    }

    bool Share_Collector::is_valid() const {
        return min > 0;
    }

    Share_Collector::DataType Share_Collector::get_raw() const {
        return data;
    }

    int32_t Share_Collector::get_min() const {
        return min;
    }

    SSS::Shares SSS::share(int32_t secret, int32_t shares, int32_t min) {
        return create_shares(shares, min, secret);
    }

    int64_t SSS::combine(const SSS::Shares& shares, int32_t min) {
        return reconstruct_from_shares(shares, min);
    }

    Share_Collector SSS::share_from_string(const std::string& secret, int32_t shares, int32_t min) {
        std::unordered_map<int32_t, std::vector<int64_t>> share_collector;
        for (int i = 1; i <= shares; ++i) {
            share_collector[i] = std::vector<int64_t>();
        }

        for (auto&& c : secret) {
            auto s = create_shares(shares, min, c);
            for (auto&& share : s) {
                share_collector[share.first].push_back(share.second);
            }
        }
        return { share_collector, min };
    }

    std::string SSS::combine_string(const Share_Collector& shares) {
        std::vector<std::pair<int32_t, std::vector<int64_t>>> prepared;
        
        size_t len = -1;
        for (auto&& entry : shares.get_raw()) {
            auto ac_len = entry.second.size();
            if (len > -1 && len != ac_len) {
                return std::string();
            }
            len = ac_len;
            prepared.push_back({entry.first, entry.second});
        }

        std::string result;
        for (int i = 0; i < len; ++i) {
            std::vector<std::pair<int32_t, int64_t>> t;
            for (auto&& e : prepared) {
                t.push_back({ e.first, e.second[i] });
            }
            result.push_back(static_cast<char>(reconstruct_from_shares(t, shares.get_min())));
        }
        if (result[result.size()-1] == '\0') {
            result = result.substr(0, result.size() -1);
        }
        return result;
    }
}