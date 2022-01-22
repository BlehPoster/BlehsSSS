#include "x_c25519.h"

#include <common/random.hpp>

#include <deps/c25519/src/c25519.h>

namespace bleh::c25519 {

	Bytes C25519_Public_Key::bytes() const {
		return data;
	}

	C25519_Public_Key C25519_Private_Key::public_key() const {
		if (data.size() != C25519_length) {
			return { {} };
		}
		Bytes pub(C25519_length);
		c25519_smult(pub.data(), c25519_base_x, data.data());
		return { pub };
	}

	Bytes C25519_Private_Key::scalar_multiplication_with(const Bytes& b) {
		Bytes r(C25519_length);
		c25519_smult(r.data(), b.data(), data.data());
		return r;
	}

	Bytes C25519_Private_Key::scalar_multiplication_with(const C25519_Public_Key& pub) {
		return scalar_multiplication_with(pub.bytes());
	}

	C25519_Private_Key C25519_Private_Key::random() {
		auto b = random::random::random_bytes(C25519_length);
		c25519_prepare(b.data());
		return { b };
	}
}