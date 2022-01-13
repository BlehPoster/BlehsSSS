#include "sss.h"

#include <random>
#include <numeric>
#include <unordered_map>
#include <sstream>

namespace bleh::sss {
    int64_t predefined_prime = static_cast<decltype(predefined_prime)>(powl(2, 31) - 1);

    std::random_device rd;
    std::mt19937 gen(rd());
    int64_t random_number_in_range(int64_t min, int64_t max) {
        std::uniform_int_distribution<int64_t> distr(min, max);
        return distr(gen);
    }

    std::vector<std::pair<int32_t, int64_t>> create_shares(int32_t shares, int32_t min_required_shares, int64_t secret) {

        decltype(create_shares(shares, min_required_shares, secret)) result;

        std::vector<decltype(random_number_in_range(0, predefined_prime))> t;
        t.push_back(secret);
        for (int i = 0; i < min_required_shares - 1; ++i) {
            auto prng = random_number_in_range(0, predefined_prime - 1);
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
        auto gcd = std::gcd(x1, y1);
        x1 /= gcd;
        y1 /= gcd;
    }

    void multiply(int64_t& x1, int64_t& y1, int64_t x2, int64_t y2)
    {
        x1 *= x2;
        y1 *= y2;
        auto gcd = std::gcd(x1, y1);
        x1 /= gcd;
        y1 /= gcd;
    }

    int64_t reconstruct_from_shares(const std::vector<std::pair<int32_t, int64_t>>& shares, int32_t min)
    {
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

    Share_Collector::DataType Share_Collector::get() const {
        return data;
    }

    std::vector<std::string> Share_Collector::stringify() const {
        decltype(stringify()) r;
        for (auto&& e : data) {
            std::stringstream ss;
            ss << std::hex << e.first;
            for (auto&& c : *e.second) {
                ss << c;
            }
            r.push_back(ss.str());
        }
        return r;
    }

    SSS::Shares SSS::share(int32_t secret, int32_t shares, int32_t min) {
        return create_shares(shares, min, secret);
    }

    int64_t SSS::combine(const SSS::Shares& shares, int32_t min) {
        return reconstruct_from_shares(shares, min);
    }

    Share_Collector SSS::share_from_string(const std::string& secret, int32_t shares, int32_t min) {
        std::unordered_map<int32_t, std::shared_ptr<std::vector<int64_t>>> share_collector;
        for (int i = 1; i <= shares; ++i) {
            share_collector[i] = std::make_shared<std::vector<int64_t>>();
        }

        for (auto&& c : secret) {
            auto s = create_shares(shares, min, c);
            for (auto&& share : s) {
                share_collector[share.first]->push_back(share.second);
            }
        }
        return share_collector;
    }

    std::string SSS::combine_string(const Share_Collector& shares, int32_t min) {

        std::vector<std::pair<int32_t, std::shared_ptr<std::vector<int64_t>>>> prepared;
        
        size_t len = -1;
        for (auto&& entry : shares.get()) {
            auto ac_len = entry.second->size();
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
                t.push_back({ e.first, (*e.second)[i] });
            }
            result.push_back(static_cast<decltype(result)::value_type>(reconstruct_from_shares(t, min)));
        }
        return result;
    }
}