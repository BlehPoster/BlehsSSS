#include <iostream>
#include <sss/sss.h>
#include <c25519/c25519.h>
#include <ed25519/ed25519.h>
#include <ecies/ecies.h>
#include <common/random.hpp>

#include <cassert>

void test_sss() {
    bleh::sss::SSS sss;

    constexpr auto share_count = 8;
    constexpr auto share_min = 2;

    auto share_secret = std::string("Lorem ipsum dolor sit amet");

    auto shares = sss.share_from_string(share_secret, share_count, share_min);
    assert(share_min == shares.get_min());

    auto secret = sss.combine_string(shares);
    assert(secret == share_secret);

    auto stringified = shares.stringify();

    auto index = 0;
    while (index + shares.get_min() <= stringified.size() - 1) {
        decltype(stringified) n;
        for (int i = index; i - index <= shares.get_min(); ++i) {
            n.push_back(stringified[i]);
        }
        auto&& remade = bleh::sss::Share_Collector::from_strings(n);
        assert(remade.is_valid());
        auto secret = sss.combine_string(remade);
        assert(secret == share_secret);
        ++index;
    }
}

void test_curve25519_shared_secret() {
    auto a = bleh::c25519::C25519_Private_Key::random();
    auto A = a.public_key();

    auto b = bleh::c25519::C25519_Private_Key::random();
    auto B = b.public_key();

    auto ss_a = a.scalar_multiplication_with(B);
    auto ss_b = b.scalar_multiplication_with(A);

    assert(ss_a.value == ss_b.value);
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

    assert(ss_a.value == ss_b.value);
}

void test_ed25519_sign() {
    auto priv = bleh::ed25519::ED25519_Private_key::random();
    auto pub = priv.sign_public_key();

    auto test = std::vector<uint8_t>{ 0xFF, 0xAA };

    auto sign = priv.sign(test);

    assert(pub.verify(sign, test));
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

    assert(d_pub.verify(sign, test));
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

    assert(rpt == pt);
}

int main(int argc, const char** argv) {
    test_sss();
    test_curve25519_shared_secret();
    test_curve25519_serialize();
    test_ed25519_sign();
    test_ed25519_serialize();
    test_ecies();

    std::cout << "no errors found" << std::endl;
    return 0;
}