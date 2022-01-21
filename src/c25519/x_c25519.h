#pragma once
#include <vector>

namespace bleh::c25519 {

	using Bytes = std::vector<uint8_t>;

	static constexpr auto C25519_length = 32;

	class C25519_Public_Key {
	public:
		C25519_Public_Key() = delete;
		C25519_Public_Key(const Bytes& o) noexcept : data(o) {}
		C25519_Public_Key(Bytes&& o) noexcept : data(std::move(o)) {}

	private:
		Bytes data;
	};

	class C25519_Private_Key {
	public:
		C25519_Private_Key() = delete;
		C25519_Private_Key(const Bytes& o) noexcept : data(o) {}
		C25519_Private_Key(Bytes&& o) noexcept : data(std::move(o)) {}

		C25519_Public_Key public_key() const;

		static C25519_Private_Key random();

	private:
		Bytes data;
	};

	class C25519 {
	public:

	};
}