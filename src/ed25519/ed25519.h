#pragma once

#include <deps/c25519/src/ed25519.h>
#include <deps/c25519/src/edsign.h>

#include <common/types.h>

#include <vector>

namespace bleh::ed25519 {

	static constexpr auto ED25519_key_length = ED25519_EXPONENT_SIZE;
	static constexpr auto ED25519_Signature_length = EDSIGN_SIGNATURE_SIZE;

	using ED25519_Scalar_Bytes = common::Bytes<uint8_t, ED25519_key_length, 0x0101>;
	using ED25519_Sign_Secret_Bytes = common::Bytes<uint8_t, ED25519_key_length, 0x0102>;
	using ED25519_Signature_Bytes = common::Bytes<uint8_t, ED25519_Signature_length, 0x0103>;

	class ED25519_Public_Key {
	public:
		ED25519_Public_Key() = delete;
		ED25519_Public_Key(const ED25519_Sign_Secret_Bytes& o) noexcept : data(o) {}
		ED25519_Public_Key(ED25519_Sign_Secret_Bytes&& o) noexcept : data(std::move(o)) {}

		ED25519_Sign_Secret_Bytes bytes() const;

		bool verify(const ED25519_Signature_Bytes& signature, const std::vector<uint8_t>& message);

		std::string serialized();
		static ED25519_Public_Key from_serialized(const std::string&);

	private:
		ED25519_Sign_Secret_Bytes data;
	};

	class ED25519_Private_key {
	public:
		ED25519_Private_key() = delete;
		ED25519_Private_key(const ED25519_Scalar_Bytes& o) noexcept : data(o) {}
		ED25519_Private_key(ED25519_Scalar_Bytes&& o) noexcept : data(std::move(o)) {}

		ED25519_Public_Key sign_public_key() const;
		ED25519_Signature_Bytes sign(const std::vector<uint8_t>& message);

		std::string serialized();

		static ED25519_Private_key random();
		static ED25519_Private_key from_serialized(const std::string&);

	private:
		ED25519_Scalar_Bytes data;
	};
}