#include <iostream>
#include <sss/sss.h>
#include <c25519/x_c25519.h>


void test_sss() {
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
}

void test_curve25519_shared_secret() {
    auto a = bleh::c25519::C25519_Private_Key::random();
    auto A = a.public_key();

    auto b = bleh::c25519::C25519_Private_Key::random();
    auto B = b.public_key();

    auto ss_a = a.scalar_multiplication_with(B);
    auto ss_b = b.scalar_multiplication_with(A);

    if (ss_a == ss_b) {
        std::cout << "created shared secret" << std::endl;
    }
    else {
        std::cout << "failed to created shared secret" << std::endl;
    }
}

int main(int argc, const char** argv) {
    test_sss();
    test_curve25519_shared_secret();

    return 0;
}