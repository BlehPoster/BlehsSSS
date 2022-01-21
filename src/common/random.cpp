#include "random.hpp"

namespace bleh::random {
	std::random_device random::rd = std::random_device();
	std::mt19937 random::gen = std::mt19937(rd());
}