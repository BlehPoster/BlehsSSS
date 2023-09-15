#pragma once

#include <c25519/c25519.h>
#include <ed25519/ed25519.h>
#include <ecies/ecies.h>
#include <sss/sss.h>

#include <src/common/random.hpp>
#include <src/common/base64.h>

#include <string>
#include <iostream>
#include <algorithm>
#include <vector>
#include <fstream>

namespace bleh {
	std::string load_file_content(const std::string& file_name);

	struct BlehSSS_Common {
		static const constexpr std::string_view property_name = "name: ";
		static const constexpr std::string_view property_c25519 = "c25519: ";
		static const constexpr std::string_view property_ed25519 = "ed25519: ";

		static const constexpr std::string_view property_ed25519_public_key = "ed_public_key: ";
		static const constexpr std::string_view property_c25519_public_key = "c_public_key: ";
		static const constexpr std::string_view property_signature = "signature: ";
		static const constexpr std::string_view property_ct = "ct: ";
	};

	class BlehSSS_Account {
	public:
		BlehSSS_Account(const std::string& name, bleh::c25519::C25519_Private_Key&& c, bleh::ed25519::ED25519_Private_key&& ed);
		BlehSSS_Account(const std::string& serialized);

		static BlehSSS_Account create(const std::string& name);

		std::string serialize();
		std::tuple<std::string, std::string> export_public_part();
		std::tuple<std::string, std::string> encrypt(const bleh::c25519::C25519_Public_Key& other_public_key, const std::string& content);
		std::string decrypt(const bleh::c25519::C25519_Public_Key& other_public_key, const std::string& ct);

		bleh::ed25519::ED25519_Public_Key ed_public_key();
		bleh::c25519::C25519_Public_Key c_public_key();

	private:
		std::string m_name;

		bleh::c25519::C25519_Private_Key m_curve25519_private_key;
		bleh::ed25519::ED25519_Private_key m_ed25519_private_key;
	};



	class BlehSSS_Handle {
	public:
		BlehSSS_Handle(const std::string& serialized);

		bool verify();
		bleh::c25519::C25519_Public_Key get_c25519_public_key() const;
		std::string name() const;

	private:
		std::string m_name;

		std::shared_ptr<bleh::c25519::C25519_Public_Key> m_curve25519_public_key;
		std::shared_ptr<bleh::ed25519::ED25519_Public_Key> m_ed25519_public_key;
		bleh::ed25519::ED25519_Signature_Bytes m_signature;
	};

	class BlehSSS_Share {
	public:
		BlehSSS_Share(const std::string& serialized);

		bool verify();

		std::string ct() const;
		bleh::c25519::C25519_Public_Key c_public_key() const;

	private:
		std::string m_name;

		std::shared_ptr<bleh::c25519::C25519_Public_Key> m_curve25519_public_key;
		std::shared_ptr<bleh::ed25519::ED25519_Public_Key> m_ed25519_public_key;
		bleh::ed25519::ED25519_Signature_Bytes m_signature;
		std::string m_ct;
	};

	class BlehSSS {
	public:
		static std::tuple<bool, std::string> create_shares(const std::string& secret, int shares, int min) {
			bleh::sss::SSS sss;
			auto result = sss.share_from_string(secret, shares, min);
			if (result.is_valid()) {
				std::stringstream stream;
				stream << "shares:\n";
				for (auto&& entry : result.stringify()) {
					std::cout << "share: " << entry << std::endl;
					stream << "\t" << entry << '\n';
				}
				return { true, stream.str()};
			}
			return { false, std::string() };
		}

		static std::string recreate_shares(const std::vector<std::string>& list) {
			auto remade = bleh::sss::Share_Collector::from_strings(list);
			bleh::sss::SSS sss;
			return sss.combine_string(remade);
		}

		static std::string create_account(const std::string& name) {
			auto account = bleh::BlehSSS_Account::create(name);
			return account.serialize();
		}

		static std::tuple<std::string, std::string> account_public_export(const std::string& account_path) {
			auto content = bleh::load_file_content(account_path);
			bleh::BlehSSS_Account account(content);
			return account.export_public_part();
		}

		static bool account_public_verify(const std::string& file_name) {
			auto content = bleh::load_file_content(file_name);
			bleh::BlehSSS_Handle handle(content);
			return handle.verify();
		}

		static std::tuple<bool, std::string, std::string> transportable_share(const std::string& share_file, int share_index, const std::string& public_part, const std::string& account_path) {
			std::string share;
			std::string line;
			std::ifstream file(share_file);
			if (file.is_open())
			{
				int index = 1;
				while (std::getline(file, line)) {
					if (line.size() > 1 && line[0] == '\t') {
						if (index == share_index) {
							share = line.substr(1);
							break;
						}
						++index;
					}
				}
				file.close();
			}
			else {
				return { false, std::string(), std::string() };
			}
			if (!share.empty()) {
				auto content = bleh::load_file_content(public_part);
				auto account_content = bleh::load_file_content(account_path);
				bleh::BlehSSS_Account account(account_content);
				bleh::BlehSSS_Handle handle(content);
				if (handle.verify()) {
					auto [ct, signature] = account.encrypt(handle.get_c25519_public_key(), share);

					std::stringstream stream;
					stream << bleh::BlehSSS_Common::property_name << handle.name() << '\n';
					stream << bleh::BlehSSS_Common::property_ct << ct << '\n';
					stream << bleh::BlehSSS_Common::property_signature << signature << '\n';
					stream << bleh::BlehSSS_Common::property_ed25519_public_key << account.ed_public_key().serialized() << '\n';
					stream << bleh::BlehSSS_Common::property_c25519_public_key << account.c_public_key().serialized() << '\n';

					return { true, stream.str(), handle.name()};
				}
			}
			return { false, std::string(), std::string() };
		}

		static std::tuple<bool, std::string> decrypt_share(const std::string& account_path, const std::string& share_file) {
			auto account_content = bleh::load_file_content(account_path);
			bleh::BlehSSS_Account account(account_content);
			auto content = bleh::load_file_content(share_file);
			bleh::BlehSSS_Share share(content);
			if (share.verify()) {
				return { true, account.decrypt(share.c_public_key(), share.ct()) };
			}
			return { false, std::string() };
		}
	};
}