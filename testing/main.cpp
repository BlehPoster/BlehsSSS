#include <iostream>
#include <sss/sss.h>
#include <c25519/x_c25519.h>
#include <ed25519/ed25519.h>


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
    std::cout << "#######" << std::endl;
}

void test_curve25519_shared_secret() {
    auto a = bleh::c25519::C25519_Private_Key::random();
    auto A = a.public_key();

    auto b = bleh::c25519::C25519_Private_Key::random();
    auto B = b.public_key();

    auto ss_a = a.scalar_multiplication_with(B);
    auto ss_b = b.scalar_multiplication_with(A);

    if (ss_a.value == ss_b.value) {
        std::cout << "successfully created shared secret" << std::endl;
    }
    else {
        std::cout << "failed to created shared secret" << std::endl;
    }
    std::cout << "#######" << std::endl;

}

void test_ed25519_sign() {
    auto priv = bleh::ed25519::ED25519_Private_key::random();
    auto pub = priv.sign_public_key();

    auto test = std::vector<uint8_t>{ 0xFF, 0xAA };

    auto sign = priv.sign(test);

    if (pub.verify(sign, test)) {
        std::cout << "ed25519 verification success" << std::endl;
    }
    else {
        std::cout << "ed25519 verification failed" << std::endl;
    }
    std::cout << "#######" << std::endl;

}

int main(int argc, const char** argv) {
    test_sss();
    test_curve25519_shared_secret();
    test_ed25519_sign();

    return 0;
}