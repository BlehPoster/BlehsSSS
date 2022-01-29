#pragma once

#include <vector>

namespace bleh::common {
	template<typename T, int len, int D, bool enable_copy_c = false>
	class Bytes {
	public:
		using C = std::vector<T>;

		Bytes() noexcept : value(len) {}
		Bytes(C&& c) noexcept : value(std::forward<C>(c)) {} // no copy constructor in case of no type deduction 
		template<typename = std::enable_if_t<enable_copy_c>>
		Bytes(const C& c) noexcept : value(c) {}

		C value;
	};
}