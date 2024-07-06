#include <ecies/ecies.h>

#include <common/random.hpp>
#include <common/sha.h>

#include <aes/aes.hpp>

namespace bleh::ecies {
	void xcrypt_ctr(uint8_t* buf, size_t len, uint8_t* secret, uint8_t* iv) {
		AES_ctx c;
		AES_init_ctx_iv(&c, secret, iv);
		AES_CTR_xcrypt_buffer(&c, buf, len);
	}

	std::tuple<Bytes, IV_Bytes> Ecies::encrypt(const Bytes& pt) {
		auto iv = random::random::random_bytes(16);
		std::vector<uint8_t> r;
		for (auto&& e : pt) {
			r.push_back(e);
		}
		xcrypt_ctr(r.data(), r.size(), secret.value.data(), iv.data());
		return { {std::move(r)}, {std::move(iv)} };
	}

	Bytes Ecies::decrypt(const Bytes& ct, const IV_Bytes& iv) {
		auto r = ct;
		auto ivc = iv;
		xcrypt_ctr(r.data(), r.size(), secret.value.data(), ivc.value.data());
		return { {std::move(r)} };
	}

	Ecies Ecies::derive_shared_secret(const c25519::C25519_Private_Key& p, const c25519::C25519_Public_Key& P) {
		auto bytes = p.scalar_multiplication_with(P);		
		auto sc = common::Sha2::sha256(bytes.value);
		return { std::move(sc) };
	}
}