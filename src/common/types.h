#pragma once

#include <vector>

namespace bleh::common {
	template<typename T, int len, int D>
	class Bytes {
	public:
		using C = std::vector<T>;

		Bytes() noexcept : value(len) {}
		Bytes(C&& c) noexcept : value(std::forward<C>(c)) {}

		C value;
	};
}