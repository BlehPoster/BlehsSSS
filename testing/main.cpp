#include <iostream>
#include "../src/sss/sss.h"

int main(int argc, const char** argv) {

    bleh::sss::SSS sss;

    auto shares = sss.share_from_string("this is a longer super secret string 123456789", 4, 2);

    auto secret = sss.combine_string(shares);

    std::cout << "from raw share: " << secret << std::endl;

    auto&& stringified = shares.stringify();
    for (auto&& e : stringified) {
        std::cout << e << std::endl;
    }

    auto&& remade = bleh::sss::Share_Collector::from_strings({ stringified[0], stringified[1] });
    if (remade.is_valid()) {
        auto secret = sss.combine_string(remade);
        std::cout << "from all serialized shares: " << secret << std::endl;
    }
    else {
        std::cout << "failed to recreate shares" << std::endl;
    }
	return 0;
}
