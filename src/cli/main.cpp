#include <c25519/c25519.h>
#include <ed25519/ed25519.h>
#include <ecies/ecies.h>
#include <sss/sss.h>

#include <common/random.hpp>

#include <src/blehsss.h>

#include <iostream>
#include <algorithm>
#include <vector>
#include <fstream>
#include <filesystem>

#ifdef _WIN32
static constexpr const char path_seperator = '\\';
#else
static constexpr const char path_seperator = '/';
#endif

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

void write_file_content(const std::string& content, const std::string& file_name) {
	if (auto pos = file_name.find_last_of(path_seperator); pos != std::string::npos) {
		std::filesystem::create_directories(file_name.substr(0, pos));
	}
	std::ofstream file;
	file.open(file_name);
	file << content;
	file.close();
}

class arg_parser {
public:
	arg_parser() = delete;
	arg_parser(int argc, const char** argv) {
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

void log(const std::string& stream) {
	std::cout << stream << std::endl;
}

class cli {
public:
	cli() = delete;
	cli(int argc, const char** argv) : args(argc, argv) { }

	int process() {
		if (args.command == "sss-share") {
			auto [secret, ok1] = args.get_arg("secret");
			auto [shares, ok2] = args.get_arg("shares");
			auto [min, ok3] = args.get_arg("min");
			auto [out_file, ok4] = args.get_arg("out");

			if (ok1 && ok2 && ok3 && ok4) {
				auto nshares = stoi(shares);
				auto nmin = stoi(min);
				secret.erase(std::remove(secret.begin(), secret.end(), '"'));

				auto[success, out] = bleh::BlehSSS::create_shares(secret, nshares, nmin);
				if (success) {
					write_file_content(out, out_file);
				}
				else {
					log("failed to create shares");
				}
			}
			else {
				log("invalid parameters");
			}
		}
		else if (args.command == "sss-recreate") {
			auto [file_name, ok1] = args.get_arg("out");

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
					auto secret = bleh::BlehSSS::recreate_shares(list);
					log("Secret: " + secret);
				}
				else {
					log("failed to load shares");
				}
			}
		}
		else if (args.command == "account-create") {
			auto [name, ok1] = args.get_arg("name");
			auto [out, ok2] = args.get_arg("out");
			if (ok1) {
				auto [serialized, error] = bleh::BlehSSS::create_account(name);
				if (error) {
					log(error.msg());
				}
				else {
					write_file_content(serialized, out);
					log("account created");
				}
			}
		}
		else if (args.command == "account-public-export") {
			auto [account_path, ok1] = args.get_arg("account");
			auto [out, ok2] = args.get_arg("out");

			if (ok1 && ok2) {
				auto content = load_file_content(account_path);
				auto [exported, name] = bleh::BlehSSS::account_public_export(content);
				write_file_content(static_cast<std::remove_reference_t<decltype(exported)>>(exported), out);
				log("public account exported");
			}
		}
		else if (args.command == "account-public-verify") {
			auto [file_name, ok1] = args.get_arg("public");
			if (ok1) {
				auto content = load_file_content(file_name);
				if (bleh::BlehSSS::account_public_verify(content)) {
					log("verify success");
				}
				else {
					log("verify error");
				}
			}
		}
		else if (args.command == "transportable-share") {
			auto [public_part, ok1] = args.get_arg("public-part");
			auto [share_number, ok2] = args.get_arg("share-number");
			auto [share_file, ok3] = args.get_arg("share-file");
			auto [account_path, ok4] = args.get_arg("account");
			auto [out_file, ok5] = args.get_arg("out");

			if (ok1 && ok2 && ok3 && ok4 && ok5) {
				auto share_index = atoi(share_number.c_str());
				auto [ok, out, name] = bleh::BlehSSS::transportable_share(share_file, share_index, load_file_content(public_part), load_file_content(account_path));

				if (ok) {
					write_file_content(out, out_file);
					log("wrote file");
				}
				else {
					log("failed to prepare data");
				}
			}
		}
		else if (args.command == "share_print") {
			auto [share_file, ok1] = args.get_arg("share-file");
			auto [account_path, ok2] = args.get_arg("account");
			if (ok1 && ok2) {
				auto[ok, secret] = bleh::BlehSSS::decrypt_share(load_file_content(account_path), load_file_content(share_file));
				if (ok) {
					log("Secret: " + secret);
				}
				else {
					log("failed to decrypt secret");
				}
			}
		}
		return 0;
	}

private:
	arg_parser args;
};

int main(int argc, const char** argv) {
	cli c(argc, argv);
	return c.process();
}