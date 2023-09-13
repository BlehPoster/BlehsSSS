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
#if 0
class BlehSSS_Account {
public:
	BlehSSS_Account(const std::string& path, const std::string& name)
		: m_file_path(path)
		, m_name(name)
		, m_curve25519_private_key(bleh::c25519::C25519_Private_Key::random())
		, m_ed25519_private_key(bleh::ed25519::ED25519_Private_key::random())
	{ }

	static BlehSSS_Account create(const std::string& path, const std::string& name);

	void store() {

	}

	void load() {

	}

private:
	std::string m_file_path;
	std::string m_name;

	bleh::c25519::C25519_Private_Key m_curve25519_private_key;
	bleh::ed25519::ED25519_Private_key m_ed25519_private_key;
};

BlehSSS_Account BlehSSS_Account::create(const std::string& path, const std::string& name) {
	return BlehSSS_Account(path, name);
}
#endif
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
*/

int main(int argc, const char** argv) {
	cli c(argc, argv);
	return c.process();
}