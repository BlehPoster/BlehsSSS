#include <blehsss.h>

#include <common/base64.h>

namespace bleh {

	const std::vector<std::string_view> BlehSSS_Common::supported_export_version = { "0.1" };

	bool BlehSSS_Common::is_supported_export_version(const std::string& version) {
		for (auto&& entry : supported_export_version) {
			if (entry == version) {
				return true;
			}
		}
		return false;
	}

	BlehSSS_Account::BlehSSS_Account(const std::string& name, bleh::c25519::C25519_Private_Key&& c, bleh::ed25519::ED25519_Private_key&& ed)
		: m_version(BlehSSS_Common::export_version)
		, m_name(name)
		, m_curve25519_private_key(std::move(c))
		, m_ed25519_private_key(std::move(ed))
	{ }

	BlehSSS_Account::BlehSSS_Account(const std::string& serialized)
		: m_version("0.0")
		, m_curve25519_private_key(decltype(m_curve25519_private_key)::random())
		, m_ed25519_private_key(decltype(m_ed25519_private_key)::random())
	{
		std::vector<std::string> lines;
		std::stringstream stream(serialized);
		std::string buffer;
		while (getline(stream, buffer, '\n')) {
			lines.push_back(buffer);
		}

		for (auto&& entry : lines) {
			if (entry.substr(0, bleh::BlehSSS_Common::property_version.size()) == bleh::BlehSSS_Common::property_version) {
				m_version = entry.substr(bleh::BlehSSS_Common::property_version.size());
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_name.size()) == bleh::BlehSSS_Common::property_name) {
				m_name = entry.substr(bleh::BlehSSS_Common::property_name.size());
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_c25519.size()) == bleh::BlehSSS_Common::property_c25519) {
				m_curve25519_private_key = decltype(m_curve25519_private_key)::from_serialized(entry.substr(bleh::BlehSSS_Common::property_c25519.size()));
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_ed25519.size()) == bleh::BlehSSS_Common::property_ed25519) {
				m_ed25519_private_key = decltype(m_ed25519_private_key)::from_serialized(entry.substr(bleh::BlehSSS_Common::property_ed25519.size()));
			}
		}
	}

	std::tuple<std::string, BlehSSS_Error> BlehSSS_Account::serialize() {
		if (!BlehSSS_Common::is_supported_export_version(m_version)) {
			return { std::string(), BlehSSS_Error("unsupported version") };
		}
		std::stringstream stream;
		stream << bleh::BlehSSS_Common::property_name << m_name << "\n";
		stream << bleh::BlehSSS_Common::property_c25519 << m_curve25519_private_key.serialized() << "\n";
		stream << bleh::BlehSSS_Common::property_ed25519 << m_ed25519_private_key.serialized() << "\n";
		return { stream.str(), BlehSSS_Error() };
	}

	std::tuple<std::string, std::string> BlehSSS_Account::export_public_part() {
		std::stringstream stream;
		stream << bleh::BlehSSS_Common::property_version << BlehSSS_Common::export_version << "\n";
		stream << bleh::BlehSSS_Common::property_name << m_name << "\n";
		stream << bleh::BlehSSS_Common::property_ed25519_public_key << m_ed25519_private_key.sign_public_key().serialized() << "\n";
		stream << bleh::BlehSSS_Common::property_c25519_public_key << m_curve25519_private_key.public_key().serialized() << "\n";
		std::vector<uint8_t> message;
		for (auto&& entry : m_name) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		for (auto&& entry : m_curve25519_private_key.public_key().serialized()) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		auto signature = m_ed25519_private_key.sign(message);
		stream << bleh::BlehSSS_Common::property_signature << signature.serialize() << "\n";
		return { stream.str(), m_name };
	}

	std::tuple<std::string, std::string> BlehSSS_Account::encrypt(const bleh::c25519::C25519_Public_Key& other_public_key, const std::string& content) {

		bleh::ecies::Bytes pt;
		for (auto&& entry : content) {
			pt.push_back(entry);
		}

		auto ecies = bleh::ecies::Ecies::derive_shared_secret(m_curve25519_private_key, other_public_key);
		auto [ct, iv] = ecies.encrypt(pt);

		std::string buffer;
		for (auto&& entry : iv.raw()) {
			buffer.push_back(entry);
		}
		for (auto&& entry : ct) {
			buffer.push_back(entry);
		}

		auto result = common::Base64::encode(buffer);
		std::vector<uint8_t> message;
		for (auto&& entry : result) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		auto signature = m_ed25519_private_key.sign(message);
		return { result, signature.serialize() };
	}

	std::string BlehSSS_Account::decrypt(const bleh::c25519::C25519_Public_Key& other_public_key, const std::string& ct) {
		auto dec_ct = common::Base64::decode(ct);
		auto iv = dec_ct.substr(0, 16);
		auto blob = dec_ct.substr(16);

		bleh::ecies::Bytes bct;
		for (auto&& entry : blob) {
			bct.push_back(entry);
		}
		bleh::ecies::Bytes biv;
		for (auto&& entry : iv) {
			biv.push_back(entry);
		}

		auto ecies = bleh::ecies::Ecies::derive_shared_secret(m_curve25519_private_key, other_public_key);
		auto pt = ecies.decrypt(bct, std::move(biv));

		std::string result;
		for (auto&& entry : pt) {
			result.push_back(entry);
		}
		return result;
	}

	bleh::ed25519::ED25519_Public_Key BlehSSS_Account::ed_public_key() {
		return m_ed25519_private_key.sign_public_key();
	}

	bleh::c25519::C25519_Public_Key BlehSSS_Account::c_public_key() {
		return m_curve25519_private_key.public_key();
	}

	BlehSSS_Account BlehSSS_Account::create(const std::string& name) {
		return BlehSSS_Account(name, bleh::c25519::C25519_Private_Key::random(), bleh::ed25519::ED25519_Private_key::random());
	}

	BlehSSS_Handle::BlehSSS_Handle(const std::string& serialized)
	{
		std::vector<std::string> lines;
		std::stringstream stream(serialized);
		std::string buffer;
		while (getline(stream, buffer, '\n')) {
			lines.push_back(buffer);
		}

		for (auto&& entry : lines) {
			if (entry.substr(0, bleh::BlehSSS_Common::property_version.size()) == bleh::BlehSSS_Common::property_version) {
				m_version = entry.substr(bleh::BlehSSS_Common::property_version.size());
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_name.size()) == bleh::BlehSSS_Common::property_name) {
				m_name = entry.substr(bleh::BlehSSS_Common::property_name.size());
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_c25519_public_key.size()) == bleh::BlehSSS_Common::property_c25519_public_key) {
				m_curve25519_public_key = std::make_shared<decltype(m_curve25519_public_key)::element_type>(decltype(m_curve25519_public_key)::element_type::from_serialized(entry.substr(bleh::BlehSSS_Common::property_c25519_public_key.size())));
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_ed25519_public_key.size()) == bleh::BlehSSS_Common::property_ed25519_public_key) {
				m_ed25519_public_key = std::make_shared<decltype(m_ed25519_public_key)::element_type>(decltype(m_ed25519_public_key)::element_type::from_serialized(entry.substr(bleh::BlehSSS_Common::property_ed25519_public_key.size())));
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_signature.size()) == bleh::BlehSSS_Common::property_signature) {
				m_signature.deserialized(entry.substr(bleh::BlehSSS_Common::property_signature.size()));
			}
		}
	}

	bool BlehSSS_Handle::verify() {
		std::vector<uint8_t> message;
		for (auto&& entry : m_name) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		for (auto&& entry : m_curve25519_public_key->serialized()) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		return m_ed25519_public_key->verify(m_signature, message);
	}

	bleh::c25519::C25519_Public_Key BlehSSS_Handle::get_c25519_public_key() const {
		return *m_curve25519_public_key;
	}

	std::string BlehSSS_Handle::name() const { return m_name; }

	BlehSSS_Share::BlehSSS_Share(const std::string& serialized)
	{
		std::vector<std::string> lines;
		std::stringstream stream(serialized);
		std::string buffer;
		while (getline(stream, buffer, '\n')) {
			lines.push_back(buffer);
		}

		for (auto&& entry : lines) {
			if (entry.substr(0, bleh::BlehSSS_Common::property_version.size()) == bleh::BlehSSS_Common::property_version) {
				m_version = entry.substr(bleh::BlehSSS_Common::property_version.size());
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_name.size()) == bleh::BlehSSS_Common::property_name) {
				m_name = entry.substr(bleh::BlehSSS_Common::property_name.size());
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_c25519_public_key.size()) == bleh::BlehSSS_Common::property_c25519_public_key) {
				m_curve25519_public_key = std::make_shared<decltype(m_curve25519_public_key)::element_type>(decltype(m_curve25519_public_key)::element_type::from_serialized(entry.substr(bleh::BlehSSS_Common::property_c25519_public_key.size())));
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_ed25519_public_key.size()) == bleh::BlehSSS_Common::property_ed25519_public_key) {
				m_ed25519_public_key = std::make_shared<decltype(m_ed25519_public_key)::element_type>(decltype(m_ed25519_public_key)::element_type::from_serialized(entry.substr(bleh::BlehSSS_Common::property_ed25519_public_key.size())));
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_signature.size()) == bleh::BlehSSS_Common::property_signature) {
				m_signature.deserialized(entry.substr(bleh::BlehSSS_Common::property_signature.size()));
			}
			else if (entry.substr(0, bleh::BlehSSS_Common::property_ct.size()) == bleh::BlehSSS_Common::property_ct) {
				m_ct = entry.substr(bleh::BlehSSS_Common::property_ct.size());
			}
		}
	}

	bool BlehSSS_Share::verify() {
		std::vector<uint8_t> message;
		for (auto&& entry : m_ct) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		return m_ed25519_public_key->verify(m_signature, message);
	}

	std::string BlehSSS_Share::ct() const { return m_ct; }
	bleh::c25519::C25519_Public_Key BlehSSS_Share::c_public_key() const { return *m_curve25519_public_key; }

	std::tuple<bool, std::string> BlehSSS::create_shares(const std::string& secret, int shares, int min) {
		bleh::sss::SSS sss;
		auto result = sss.share_from_string(secret, shares, min);
		if (result.is_valid()) {
			std::stringstream stream;
			stream << "shares:\n";
			for (auto&& entry : result.stringify()) {
				std::cout << "share: " << entry << std::endl;
				stream << "\t" << entry << '\n';
			}
			return { true, stream.str() };
		}
		return { false, std::string() };
	}

	std::string BlehSSS::recreate_shares(const std::vector<std::string>& list) {
		auto remade = bleh::sss::Share_Collector::from_strings(list);
		bleh::sss::SSS sss;
		return sss.combine_string(remade);
	}

	std::tuple<std::string, BlehSSS_Error> BlehSSS::create_account(const std::string& name) {
		auto account = bleh::BlehSSS_Account::create(name);
		return account.serialize();
	}

	std::tuple<std::string, std::string> BlehSSS::account_public_export(const std::string& serialized) {
		bleh::BlehSSS_Account account(serialized);
		return account.export_public_part();
	}

	bool BlehSSS::account_public_verify(const std::string& serialized) {
		bleh::BlehSSS_Handle handle(serialized);
		return handle.verify();
	}

	std::tuple<bool, std::string, std::string> BlehSSS::transportable_share(const std::string& share_file, int share_index, const std::string& public_part, const std::string& account) {
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
			bleh::BlehSSS_Account account(account);
			bleh::BlehSSS_Handle handle(public_part);
			if (handle.verify()) {
				auto [ct, signature] = account.encrypt(handle.get_c25519_public_key(), share);

				std::stringstream stream;
				stream << bleh::BlehSSS_Common::property_version << BlehSSS_Common::export_version << '\n';
				stream << bleh::BlehSSS_Common::property_name << handle.name() << '\n';
				stream << bleh::BlehSSS_Common::property_ct << ct << '\n';
				stream << bleh::BlehSSS_Common::property_signature << signature << '\n';
				stream << bleh::BlehSSS_Common::property_ed25519_public_key << account.ed_public_key().serialized() << '\n';
				stream << bleh::BlehSSS_Common::property_c25519_public_key << account.c_public_key().serialized() << '\n';

				return { true, stream.str(), handle.name() };
			}
		}
		return { false, std::string(), std::string() };
	}

	std::tuple<bool, std::string> BlehSSS::decrypt_share(const std::string& account_content, const std::string& share_content) {
		bleh::BlehSSS_Account account(account_content);
		bleh::BlehSSS_Share share(share_content);
		if (share.verify()) {
			return { true, account.decrypt(share.c_public_key(), share.ct()) };
		}
		return { false, std::string() };
	}
}