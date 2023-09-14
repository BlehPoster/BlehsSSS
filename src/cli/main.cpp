#include <c25519/c25519.h>
#include <ed25519/ed25519.h>

#include <sss/sss.h>

#include <iostream>
#include <algorithm>
#include <vector>
#include <fstream>

class arg_parser {
public:
	arg_parser() = delete;
	arg_parser(int argc, const char** argv) {
#ifdef _WIN32
		static constexpr const char path_seperator = '\\';
#else
		static constexpr const char path_seperator = '/';
#endif
		for (int i = 0; i < argc; ++i) {
			raw.push_back(argv[i]);
			if (i == 0) {
				std::string buffer = argv[i];
				path = buffer.substr(0, buffer.find_last_of(path_seperator) + 1);
			}
			else if (i == 1) {
				command = argv[i];
			}
			else {
				args.push_back(argv[i]);
			}
		}
	}

	std::pair<std::string, bool> get_arg(const std::string& ident) {
		auto fixed = std::string("--") + ident + "=";
		for (auto e : args) {
			if (e.find(fixed) != std::string::npos) {
				return { e.substr(fixed.size()), true };
			}
		}
		return { std::string(), false };
	}

	std::vector<std::string> raw;

	std::string path;
	std::string command;
	std::vector<std::string> args;
};

std::string load_file_content(const std::string& file_name) {
	std::string line;
	std::ifstream file(file_name);
	std::string content;
	if (file.is_open())
	{
		while (std::getline(file, line)) {
			content.append(line + '\n');
		}
		file.close();
	}
	return content;
}

static const constexpr std::string_view property_name = "name: ";
static const constexpr std::string_view property_c25519 = "c25519: ";
static const constexpr std::string_view property_ed25519 = "ed25519: ";

static const constexpr std::string_view property_ed25519_public_key = "ed_public_key: ";
static const constexpr std::string_view property_c25519_public_key = "c_public_key: ";
static const constexpr std::string_view property_signature = "signature: ";

class BlehSSS_Account {
public:
	BlehSSS_Account(const std::string& name, bleh::c25519::C25519_Private_Key&& c, bleh::ed25519::ED25519_Private_key&& ed)
		: m_name(name)
		, m_curve25519_private_key(std::move(c))
		, m_ed25519_private_key(std::move(ed))
	{ }

	BlehSSS_Account(const std::string& serialized)
		: m_curve25519_private_key(decltype(m_curve25519_private_key)::random())
		, m_ed25519_private_key(decltype(m_ed25519_private_key)::random())
	{
		std::vector<std::string> lines;
		std::stringstream stream(serialized);
		std::string buffer;
		while (getline(stream, buffer, '\n')) {
			lines.push_back(buffer);
		}

		for (auto&& entry : lines) {
			
			if (entry.substr(0, property_name.size()) == property_name) {
				m_name = entry.substr(property_name.size());
			}
			else if (entry.substr(0, property_c25519.size()) == property_c25519) {
				m_curve25519_private_key = decltype(m_curve25519_private_key)::from_serialized(entry.substr(property_c25519.size()));
			}
			else if (entry.substr(0, property_ed25519.size()) == property_ed25519) {
				m_ed25519_private_key = decltype(m_ed25519_private_key)::from_serialized(entry.substr(property_ed25519.size()));
			}
		}
	}

	static BlehSSS_Account create(const std::string& name);

	std::string serialize() {
		std::stringstream stream;
		stream << property_name << m_name << "\n";
		stream << property_c25519 << m_curve25519_private_key.serialized() << "\n";
		stream << property_ed25519 << m_ed25519_private_key.serialized() << "\n";
		return stream.str();
	}

	std::tuple<std::string, std::string> export_public_part() {
		std::stringstream stream;
		stream << property_name << m_name << "\n";
		stream << property_ed25519_public_key << m_ed25519_private_key.sign_public_key().serialized() << "\n";
		stream << property_c25519_public_key << m_curve25519_private_key.public_key().serialized() << "\n";
		std::vector<uint8_t> message;
		for (auto&& entry : m_name) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		for (auto&& entry : m_curve25519_private_key.public_key().serialized()) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		auto signature = m_ed25519_private_key.sign(message);
		stream << property_signature << signature.serialize() << "\n";
		return { stream.str(), m_name };
	}

private:
	std::string m_name;

	bleh::c25519::C25519_Private_Key m_curve25519_private_key;
	bleh::ed25519::ED25519_Private_key m_ed25519_private_key;
};

BlehSSS_Account BlehSSS_Account::create(const std::string& name) {
	return BlehSSS_Account(name, bleh::c25519::C25519_Private_Key::random(), bleh::ed25519::ED25519_Private_key::random());
}

class BlehSSS_Handle {
public:
	BlehSSS_Handle(const std::string& serialized)
	{
		std::vector<std::string> lines;
		std::stringstream stream(serialized);
		std::string buffer;
		while (getline(stream, buffer, '\n')) {
			lines.push_back(buffer);
		}

		for (auto&& entry : lines) {

			if (entry.substr(0, property_name.size()) == property_name) {
				m_name = entry.substr(property_name.size());
			}
			else if (entry.substr(0, property_c25519_public_key.size()) == property_c25519_public_key) {
				m_curve25519_public_key = std::make_shared<decltype(m_curve25519_public_key)::element_type>(decltype(m_curve25519_public_key)::element_type::from_serialized(entry.substr(property_c25519_public_key.size())));
			}
			else if (entry.substr(0, property_ed25519_public_key.size()) == property_ed25519_public_key) {
				m_ed25519_public_key = std::make_shared<decltype(m_ed25519_public_key)::element_type>(decltype(m_ed25519_public_key)::element_type::from_serialized(entry.substr(property_ed25519_public_key.size())));
			}
			else if (entry.substr(0, property_signature.size()) == property_signature) {
				m_signature.deserialized(entry.substr(property_signature.size()));
			}
		}
	}

	bool verify() {
		std::vector<uint8_t> message;
		for (auto&& entry : m_name) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		for (auto&& entry : m_curve25519_public_key->serialized()) {
			message.push_back(static_cast<uint8_t>(entry));
		}
		return m_ed25519_public_key->verify(m_signature, message);
	}

private:
	std::string m_name;

	std::shared_ptr<bleh::c25519::C25519_Public_Key> m_curve25519_public_key;
	std::shared_ptr<bleh::ed25519::ED25519_Public_Key> m_ed25519_public_key;
	bleh::ed25519::ED25519_Signature_Bytes m_signature;
};

class cli {
public:
	cli() = delete;
	cli(int argc, const char** argv) : args(argc, argv) { }

	int process() {
		if (args.command == "sss-share") {
			auto [secret, ok1] = args.get_arg("secret");
			auto [shares, ok2] = args.get_arg("shares");
			auto [min, ok3] = args.get_arg("min");

			if (ok1 && ok2 && ok3) {
				auto nshares = stoi(shares);
				auto nmin = stoi(min);

				secret.erase(std::remove(secret.begin(), secret.end(), '"'));
				bleh::sss::SSS sss;
				auto result = sss.share_from_string(secret, nshares, nmin);
				if (!result.is_valid()) {
					std::cout << "failed to get shares" << std::endl;
				}
				else {
					std::ofstream file;
					file.open(std::string("shares-") + std::to_string(std::time(nullptr)) + ".dat");
					file << "shares:\n";
					for (auto&& entry : result.stringify()) {
						std::cout << "share: " << entry << std::endl;
						file << "\t" << entry << '\n';
					}
				}
			}
		}
		else if (args.command == "sss-recreate") {
			auto [file_name, ok1] = args.get_arg("name");

			if (ok1) {
				std::string line;
				std::ifstream file(file_name);
				std::vector<std::string> list;
				if (file.is_open())
				{
					while (std::getline(file, line)) {
						if (line.size() > 1 && line[0] == '\t') {
							list.push_back(line.substr(1));
						}
					}
					file.close();
				}
				if (!list.empty()) {
					auto remade = bleh::sss::Share_Collector::from_strings(list);
					bleh::sss::SSS sss;
					auto secret = sss.combine_string(remade);

					std::cout << "Secret: " << secret << std::endl;
				}
				else {
					std::cout << "failed to load shares" << std::endl;
				}
			}
		}
		else if (args.command == "account-create") {
			auto [name, ok1] = args.get_arg("name");
			if (ok1) {
				auto account = BlehSSS_Account::create(name);
				std::ofstream file;
				file.open(std::string("blehsss-account.dat"));
				file << account.serialize();
				std::cout << "account created" << std::endl;
			}
		}
		else if (args.command == "account-public-export") {
			auto content = load_file_content("blehsss-account.dat");
			BlehSSS_Account account(content);
			auto [exported, name] = account.export_public_part();
			std::ofstream ofile;
			ofile.open(std::string("blehsss-account-public-" + name + ".dat"));
			ofile << static_cast<std::remove_reference_t<decltype(exported)>>(exported);
			std::cout << "public account exported" << std::endl;
		}
		else if (args.command == "account-public-verify") {
			auto [file_name, ok1] = args.get_arg("name");
			if (ok1) {
				auto content = load_file_content(file_name);
				BlehSSS_Handle handle(content);
				if (handle.verify()) {
					std::cout << "verify success" << std::endl;
				}
				else {
					std::cout << "verify error" << std::endl;
				}
			}
		}
		return 0;
	}

private:
	arg_parser args;
};

/*
* format: blesss_cli [command] -[args ...]
* 
* sss-share --secret="hallo world" --shares=5 --min=2
* sss-recreate --name=shares-<timestamp>.dat
* 
* account-create --name=bleh
* account-public-export
* account-public-verify --name=blehsss-account-public-bleh.dat
* 
*/

int main(int argc, const char** argv) {
	cli c(argc, argv);
	return c.process();
}