#include <iostream>
#include "../src/sss.h"

int main(int argc, const char** argv) {

    bleh::sss::SSS sss;

    auto shares = sss.share_from_string("i am a test string", 4, 2);

    for (auto&& e : shares.stringify()) {
        std::cout << e << std::endl;
    }
    
    auto secret = sss.combine_string(shares, 2);

    std::cout << secret << std::endl;
    
	return 0;
}