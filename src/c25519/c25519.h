#pragma once

#include <common/types.h>

#include <deps/c25519/src/c25519.h>
#include <vector>

namespace bleh::c25519 {
	static constexpr auto C25519_length = C25519_EXPONENT_SIZE;

	using C25519_Scalar_Bytes = common::Bytes<uint8_t, C25519_length, 0x0001>;
	using C25519_CX_Bytes = common::Bytes<uint8_t, C25519_length, 0x0002>;

	class C25519_Public_Key {
	public:
		C25519_Public_Key() = delete;
		C25519_Public_Key(const C25519_CX_Bytes& o) noexcept : data(o) {}
		C25519_Public_Key(C25519_CX_Bytes&& o) noexcept : data(std::move(o)) {}

		C25519_CX_Bytes bytes() const;

	private:
		C25519_CX_Bytes data;
	};

	class C25519_Private_Key {
	public:
		C25519_Private_Key() = delete;
		C25519_Private_Key(const C25519_Scalar_Bytes& o) noexcept : data(o) {}
		C25519_Private_Key(C25519_Scalar_Bytes&& o) noexcept : data(std::move(o)) {}

		C25519_Public_Key public_key() const;

		C25519_CX_Bytes scalar_multiplication_with(const C25519_CX_Bytes& b) const;
		C25519_CX_Bytes scalar_multiplication_with(const C25519_Public_Key& pub) const;

		static C25519_Private_Key random();

	private:
		C25519_Scalar_Bytes data;
	};
}