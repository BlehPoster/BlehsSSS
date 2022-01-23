#include "sss.h"

#include <common/random.hpp>

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

    void addition(int64_t& x1, int64_t& y1, int64_t x2, int64_t y2) {
        x1 = x1 * y2 + y1 * x2;
        y1 *= y2;
    }

    void multiply(int64_t& x1, int64_t& y1, int64_t x2, int64_t y2) {
        x1 *= x2;
        y1 *= y2;
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
                    int64_t xn = x[o];
                    int64_t xd = x[i] - x[o];
                    multiply(yn, yd, xn, xd);
                }
            }
            addition(n, d, yn, yd);
        }
        return n;
    }

    std::vector<std::string> Share_Collector::stringify() const {
        decltype(stringify()) r;
        for (auto&& e : data) {
            
            std::stringstream ss;
            ss << std::hex << 0x01 << e.first << min;

            for (auto&& c : e.second) {
                static auto ins = [&](auto&& x) {
                    if (x < 0x10) {
                        ss << '0';
                    }
                    ss << x;
                };
                ins(c & 0x000000FF);
                ins((c & 0x0000FF00) >> 8);
                ins((c & 0x00FF0000) >> 16);
                ins((c & 0xFF000000) >> 24);
            }

            r.push_back(ss.str());
        }
        return r;
    }

    Share_Collector Share_Collector::from_strings(const std::vector<std::string>& strings) {
        DataType r;
        int32_t min = 0;
        for (auto&& str : strings) {
            std::istringstream iss(str);
            int index = 0;
            char h = 0;

            int32_t share_index = 0;
            auto e = std::vector<int64_t>();

            while (iss) {
                if (index == 0) {
                    iss >> std::hex >> h;
                    if ((h - '0') != 0x01) {
                        return { {}, 0 };
                    }
                }
                else if (index == 1) {
                    iss >> h;
                    share_index = h - '0';
                }
                else if(index == 2) {
                    iss >> h;
                    min = h - '0';
                }
                else {
                    static auto g = [&]() -> int64_t {
                        char h, l;
                        iss >> h >> l;
                        std::stringstream tss;
                        tss << std::hex << h << l;
                        int r;
                        tss >> r;
                        return r;
                    };
                    auto v = g() | (g() << 8) | (g() << 16) | (g() << 24);
                    e.push_back(v);
                }
                ++index;
            }
            r[share_index] = e;
        }
        return { r, min };
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
            result.push_back(static_cast<decltype(result)::value_type>(reconstruct_from_shares(t, shares.get_min())));
        }
        return result;
    }
}