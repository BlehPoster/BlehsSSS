#include "c25519.h"

#include <common/random.hpp>

#include <deps/c25519/src/c25519.h>

namespace bleh::c25519 {

	C25519_CX_Bytes C25519_Public_Key::bytes() const {
		return data;
	}

	C25519_Public_Key C25519_Private_Key::public_key() const {
		if (data.value.size() != C25519_length) {
			return { {} };
		}
		C25519_CX_Bytes pub;
		c25519_smult(pub.value.data(), c25519_base_x, data.value.data());
		return { pub };
	}

	C25519_CX_Bytes C25519_Private_Key::scalar_multiplication_with(const C25519_CX_Bytes& b) {
		C25519_CX_Bytes r;
		c25519_smult(r.value.data(), b.value.data(), data.value.data());
		return r;
	}

	C25519_CX_Bytes C25519_Private_Key::scalar_multiplication_with(const C25519_Public_Key& pub) {
		return scalar_multiplication_with(pub.bytes());
	}

	C25519_Private_Key C25519_Private_Key::random() {
		C25519_Scalar_Bytes b = random::random::random_bytes(C25519_length);
		c25519_prepare(b.value.data());
		return { b };
	}
}