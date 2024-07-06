#include <ed25519/ed25519.h>

#include <common/random.hpp>

#include <c25519/src/edsign.h>

namespace bleh::ed25519 {
	ED25519_Sign_Secret_Bytes ED25519_Public_Key::bytes() const {
		return data;
	}

	bool ED25519_Public_Key::verify(const ED25519_Signature_Bytes& signature, const std::vector<uint8_t>& message) {
		return edsign_verify(signature.value.data(), data.value.data(), message.data(), message.size());
	}

	std::string ED25519_Public_Key::serialized() {
		return data.serialize();
	}

	ED25519_Public_Key ED25519_Public_Key::from_serialized(const std::string& ser) {
		ED25519_Sign_Secret_Bytes r;
		r.deserialized(ser);
		return { r };
	}

	ED25519_Public_Key ED25519_Private_key::sign_public_key() const {
		if (data.value.size() != ED25519_key_length) {
			return { {} };
		}
		ED25519_Sign_Secret_Bytes pub;
		edsign_sec_to_pub(pub.value.data(), data.value.data());
		return { pub };
	}
		
	ED25519_Signature_Bytes ED25519_Private_key::sign(const std::vector<uint8_t>& message) {
		ED25519_Signature_Bytes r;
		auto pub = sign_public_key();
		edsign_sign(r.value.data(), pub.bytes().value.data(), data.value.data(), message.data(), message.size());
		return r;
	}

	std::string ED25519_Private_key::serialized() {
		return data.serialize();
	}

	ED25519_Private_key ED25519_Private_key::random() {
		ED25519_Scalar_Bytes b = random::random::random_bytes(ED25519_key_length);
		ed25519_prepare(b.value.data());
		return { b };
	}

	ED25519_Private_key ED25519_Private_key::from_serialized(const std::string& ser) {
		ED25519_Scalar_Bytes r;
		r.deserialized(ser);
		return { r };
	}
}