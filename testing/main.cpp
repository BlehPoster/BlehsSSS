#include <iostream>
#include <sss/sss.h>
#include <c25519/c25519.h>
#include <ed25519/ed25519.h>
#include <ecies/ecies.h>
#include <common/random.hpp>


void test_sss() {
    bleh::sss::SSS sss;
    auto shares = sss.share_from_string("this is a long string used as secret ->>>>> secret", 5, 3);

    auto secret = sss.combine_string(shares);

    std::cout << "from raw share: " << secret << std::endl;

    auto stringified = shares.stringify();
    for (auto&& e : stringified) {
        std::cout << e << std::endl;
    }

    decltype(stringified) n;
    for (int i = 0; i < shares.get_min(); ++i) {
        n.push_back(stringified[i]);
    }
    auto&& remade = bleh::sss::Share_Collector::from_strings(n);
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

    if (ss_a.value == ss_b.value) {
        std::cout << "successfully created shared secret" << std::endl;
    }
    else {
        std::cout << "failed to created shared secret" << std::endl;
    }
}

void test_curve25519_serialize() {
    auto a = bleh::c25519::C25519_Private_Key::random();
    auto A = a.public_key();

    auto b = bleh::c25519::C25519_Private_Key::random();
    auto B = b.public_key();

    auto ser_a = a.serialized();
    auto ser_A = A.serialized();

    auto ra = bleh::c25519::C25519_Private_Key::from_serialized(ser_a);
    auto rA = bleh::c25519::C25519_Public_Key::from_serialized(ser_A);

    auto ss_a = ra.scalar_multiplication_with(B);
    auto ss_b = b.scalar_multiplication_with(rA);

    if (ss_a.value == ss_b.value) {
        std::cout << "successfully created shared secret from serialized" << std::endl;
    }
    else {
        std::cout << "failed to created shared secret from serialized" << std::endl;
    }
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
}

void test_ed25519_serialize() {
    auto priv = bleh::ed25519::ED25519_Private_key::random();
    auto s_priv = priv.serialized();
    auto d_priv = bleh::ed25519::ED25519_Private_key::from_serialized(s_priv);
    auto pub = priv.sign_public_key();

    auto test = std::vector<uint8_t>{ 0xFF, 0xAA };

    auto sign = d_priv.sign(test);

    auto s_pub = pub.serialized();
    auto d_pub = bleh::ed25519::ED25519_Public_Key::from_serialized(s_pub);

    if (d_pub.verify(sign, test)) {
        std::cout << "ed25519 verification success from serialized" << std::endl;
    }
    else {
        std::cout << "ed25519 verification failed from serialized" << std::endl;
    }
}

void test_ecies() {
    auto a = bleh::c25519::C25519_Private_Key::random();
    auto A = a.public_key();
    auto b = bleh::c25519::C25519_Private_Key::random();
    auto B = b.public_key();

    auto ss_a = bleh::ecies::Ecies::derive_shared_secret(a, B);
    auto ss_b = bleh::ecies::Ecies::derive_shared_secret(b, A);

    auto pt = bleh::random::random::random_bytes(20);

    auto[ct, iv] = ss_a.encrypt(pt);
    auto rpt = ss_b.decrypt(ct, iv);

    if (rpt == pt) {
        std::cout << "ecies encrypt/decrypt success" << std::endl;
    }
    else {
        std::cout << "ecies encrypt/decrypt failed" << std::endl;
    }
}

int main(int argc, const char** argv) {
    test_sss();
    std::cout << "#######" << std::endl;
    test_curve25519_shared_secret();
    std::cout << "#######" << std::endl;
    test_curve25519_serialize();
    std::cout << "#######" << std::endl;
    test_ed25519_sign();
    std::cout << "#######" << std::endl;
    test_ed25519_serialize();
    std::cout << "#######" << std::endl;
    test_ecies();
    return 0;
}