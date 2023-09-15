#include <c25519/c25519.h>
#include <ed25519/ed25519.h>
#include <ecies/ecies.h>
#include <sss/sss.h>

#include <src/common/random.hpp>
#include <src/common/base64.h>

#include <src/blehsss.h>

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
					std::ofstream file;
					file.open(out_file);
					file << out;
					file.close();
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
				auto serialized = bleh::BlehSSS::create_account(name);
				std::ofstream file;
				file.open(out);
				file << serialized;
				file.close();
				log("account created");
			}
		}
		else if (args.command == "account-public-export") {
			auto [account_path, ok1] = args.get_arg("account");
			auto [out, ok2] = args.get_arg("out");

			if (ok1 && ok2) {
				auto [exported, name] = bleh::BlehSSS::account_public_export(account_path);
				std::ofstream ofile;
				ofile.open(out);
				ofile << static_cast<std::remove_reference_t<decltype(exported)>>(exported);
				ofile.close();
				log("public account exported");
			}
		}
		else if (args.command == "account-public-verify") {
			auto [file_name, ok1] = args.get_arg("name");
			if (ok1) {
				if (bleh::BlehSSS::account_public_verify(file_name)) {
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
				auto [ok, out, name] = bleh::BlehSSS::transportable_share(share_file, share_index, public_part, account_path);

				if (ok) {
					std::ofstream file;
					file.open(out_file);
					file << out;
					file.close();
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
				auto[ok, secret] = bleh::BlehSSS::decrypt_share(account_path, share_file);
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

/*
* format: blesss_cli [command] -[args ...]
* 
* .\cli sss-share --secret="hallo world" --shares=5 --min=2 --out=data\shares.dat
* .\cli sss-recreate --name=data\shares.dat
* 
* .\cli account-create --name=bleh --out=data\blehsss-account-bleh.dat
* .\cli account-public-export --account=data\blehsss-account-bleh.dat --out=data\blehsss-account-public-bleh.dat
* .\cli account-public-verify --name=data\blehsss-account-public-bleh.dat
* 
* .\cli transportable-share --public-part=data\blehsss-account-public-bleh.dat --share-file=shares.dat --share-number=1 --account=data\blehsss-account-bleh.dat --out=data\encrypted-share-bleh.dat
* .\cli share_print --share-file=data\encrypted-share-bleh.dat --name=data\blehsss-account-public-bleh.dat --account=data\blehsss-account-bleh.dat
* 
*/

int main(int argc, const char** argv) {
	cli c(argc, argv);
	return c.process();
}