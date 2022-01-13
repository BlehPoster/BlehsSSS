#include <iostream>
#include <inttypes.h>
#include <random>
#include <numeric>
#include <unordered_map>

int64_t predefined_prime = powl(2, 31) -1;

std::random_device rd;
std::mt19937 gen(rd());
int64_t random_number_in_range(int64_t min, int64_t max) {
	std::uniform_int_distribution<int64_t> distr(min, max);
    return distr(gen);
}

std::vector<std::pair<uint32_t, int64_t>> create_shares(int32_t shares, int32_t min_required_shares, int64_t secret) {

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
		result.push_back({x, y});
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

int64_t reconstruct_from_shares(const std::vector<std::pair<uint32_t, int64_t>>& shares, int32_t min)
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

void test1() {
    int64_t secret = 1234;
    auto shares_to_create = 4;
    auto min_shares_to_recreate = 2;

    auto shares = create_shares(shares_to_create, min_shares_to_recreate, secret);

    std::cout << "predefined prime: " << predefined_prime << std::endl;

    for (auto&& e : shares) {
        std::cout << "index: " << e.first << " - share: " << e.second << std::endl;
    }

    decltype(shares) min_shares;
    for (int i = 0; i < min_shares_to_recreate; ++i) {
        min_shares.push_back(shares[i]);
    }

    auto res = reconstruct_from_shares(min_shares, min_shares_to_recreate);
    std::cout << res << std::endl;

    for (int i = 0; i < min_shares_to_recreate; ++i) {
        min_shares.push_back(shares[i + (min_shares_to_recreate - 1)]);
    }

    res = reconstruct_from_shares(min_shares, min_shares_to_recreate);
    std::cout << res << std::endl;
}

void test2() {
    std::string secret_string = "super secret string";
    auto shares_to_create = 4;
    auto min_shares_to_recreate = 2;

    std::unordered_map<int32_t, std::shared_ptr<std::vector<int64_t>>> share_collector;
    for (int i = 1; i <= shares_to_create; ++i) {
        share_collector[i] = std::make_shared<std::vector<int64_t>>();
    }

    for (auto&& c : secret_string) {
        auto shares = create_shares(shares_to_create, min_shares_to_recreate, c);
        for (auto&& share : shares) {
            share_collector[share.first]->push_back(share.second);
        }
    }

    int32_t id_1;
    int32_t id_2;
    std::vector<int64_t> buffer_1;
    std::vector<int64_t> buffer_2;
    {
        int i = 0;
        for (auto&& e : share_collector) {
            if (i == 0) {
                id_1 = e.first;
                buffer_1 = *e.second;
            }
            else if (i == 1) {
                id_2 = e.first;
                buffer_2 = *e.second;
            }
            ++i;
        }
    }

    if (buffer_1.size() != buffer_2.size()) {
        std::cout << "buffer size different" << std::endl;
        return;
    }

    std::string result;
    for (int i = 0; i < buffer_1.size(); ++i) {
        std::vector<std::pair<uint32_t, int64_t>> t{ {id_1, buffer_1[i]}, {id_2, buffer_2[i]} };
        auto&& r = reconstruct_from_shares(t, min_shares_to_recreate);
        result.push_back(r);
    }

    std::cout << result << std::endl;
}

int main(int argc, const char** argv) {

    //test1();
    test2();
    
	return 0;
}