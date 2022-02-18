#pragma once

#include <common/base64.h>

#include <vector>
#include <sstream>

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

		template<typename = std::enable_if_t<std::is_same_v<T, uint8_t>>>
		std::string serialize() {
			std::string buffer;
			std::copy(value.begin(), value.end(), std::back_inserter(buffer));
			return base64_encode(buffer);
		}

		template<typename = std::enable_if_t<std::is_same_v<T, uint8_t>>>
		void deserialized(const std::string& data) {
			auto buffer = base64_decode(data);
			if (buffer.size() == len) {
				std::copy(buffer.begin(), buffer.end(), value.begin());
			}
		}
	};
}