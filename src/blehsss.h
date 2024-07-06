#pragma once

#include <c25519/c25519.h>
#include <ed25519/ed25519.h>
#include <ecies/ecies.h>
#include <sss/sss.h>

#include <common/random.hpp>
#include <base64/base64.h>

#include <string>
#include <iostream>
#include <algorithm>
#include <vector>
#include <fstream>

namespace bleh {
	struct BlehSSS_Common {
		static const constexpr std::string_view property_version = "version: ";
		static const constexpr std::string_view property_name = "name: ";
		static const constexpr std::string_view property_c25519 = "c25519: ";
		static const constexpr std::string_view property_ed25519 = "ed25519: ";

		static const constexpr std::string_view property_ed25519_public_key = "ed_public_key: ";
		static const constexpr std::string_view property_c25519_public_key = "c_public_key: ";
		static const constexpr std::string_view property_signature = "signature: ";
		static const constexpr std::string_view property_ct = "ct: ";

		static const constexpr std::string_view export_version = "0.1";
		static const std::vector<std::string_view> supported_export_version;

		static bool is_supported_export_version(const std::string& version);
	};

	class BlehSSS_Error {
	public:
		BlehSSS_Error() = default;
		BlehSSS_Error(const std::string& msg) : m_msg(msg) { }

		operator bool() { return !m_msg.empty(); }
		auto msg() const { return m_msg; }

	private:
		std::string m_msg;
	};

	class BlehSSS_Account {
	public:
		BlehSSS_Account(const std::string& name, bleh::c25519::C25519_Private_Key&& c, bleh::ed25519::ED25519_Private_key&& ed);
		BlehSSS_Account(const std::string& serialized);

		static BlehSSS_Account create(const std::string& name);

		std::tuple<std::string, BlehSSS_Error> serialize();
		std::tuple<std::string, std::string> export_public_part();
		std::tuple<std::string, std::string> encrypt(const bleh::c25519::C25519_Public_Key& other_public_key, const std::string& content);
		std::string decrypt(const bleh::c25519::C25519_Public_Key& other_public_key, const std::string& ct);

		bleh::ed25519::ED25519_Public_Key ed_public_key();
		bleh::c25519::C25519_Public_Key c_public_key();

	private:
		std::string m_version;
		std::string m_name;

		bleh::c25519::C25519_Private_Key m_curve25519_private_key;
		bleh::ed25519::ED25519_Private_key m_ed25519_private_key;
	};

	class BlehSSS_Handle {
	public:
		BlehSSS_Handle() = delete;
		BlehSSS_Handle(const std::string& serialized);

		bool verify();
		bleh::c25519::C25519_Public_Key get_c25519_public_key() const;
		std::string name() const;

	private:
		std::string m_version;
		std::string m_name;

		std::shared_ptr<bleh::c25519::C25519_Public_Key> m_curve25519_public_key;
		std::shared_ptr<bleh::ed25519::ED25519_Public_Key> m_ed25519_public_key;
		bleh::ed25519::ED25519_Signature_Bytes m_signature;
	};

	class BlehSSS_Share {
	public:
		BlehSSS_Share() = delete;
		BlehSSS_Share(const std::string& serialized);

		bool verify();

		std::string ct() const;
		bleh::c25519::C25519_Public_Key c_public_key() const;

	private:
		std::string m_version;
		std::string m_name;

		std::shared_ptr<bleh::c25519::C25519_Public_Key> m_curve25519_public_key;
		std::shared_ptr<bleh::ed25519::ED25519_Public_Key> m_ed25519_public_key;
		bleh::ed25519::ED25519_Signature_Bytes m_signature;
		std::string m_ct;
	};

	class BlehSSS {
	public:
		static std::tuple<bool, std::string> create_shares(const std::string& secret, int shares, int min);
		static std::string recreate_shares(const std::vector<std::string>& list);
		static std::tuple<std::string, BlehSSS_Error> create_account(const std::string& name);
		static std::tuple<std::string, std::string> account_public_export(const std::string& serialized);
		static bool account_public_verify(const std::string& serialized);
		static std::tuple<bool, std::string, std::string> transportable_share(const std::string& share_file, int share_index, const std::string& public_part, const std::string& account);
		static std::tuple<bool, std::string> decrypt_share(const std::string& account_content, const std::string& share_content);
	};
}