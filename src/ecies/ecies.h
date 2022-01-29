#pragma once

#include <c25519/c25519.h>

#include <common/types.h>

#include <memory>

namespace bleh::ecies {
	using Shared_Secret_Bytes = common::Bytes<uint8_t, 32, 0x0200>;
	using IV_Bytes = common::Bytes<uint8_t, 16, 0x0202>;

	using Bytes = std::vector<uint8_t>;

	class Ecies {
	public:
		Ecies() = delete;
		Ecies(const Shared_Secret_Bytes& s) noexcept : secret(s) {}
		Ecies(Shared_Secret_Bytes&& s) noexcept : secret(std::move(s)) {}

		std::tuple<Bytes, IV_Bytes> encrypt(const Bytes& pt);
		Bytes decrypt(const Bytes& ct, const IV_Bytes& iv);

		static Ecies derive_shared_secret(const c25519::C25519_Private_Key& p, const c25519::C25519_Public_Key& P);

	private:
		Shared_Secret_Bytes secret;
	};
}