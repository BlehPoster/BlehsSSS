#include <common/sha.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

namespace bleh::common {

    std::vector<uint8_t> Sha2::sha256(const std::vector<uint8_t>& in) {
        auto hash = std::vector<uint8_t>(SHA256_DIGEST_LENGTH, '\0');
        unsigned int md_len = 0;

        auto md = EVP_sha256();
        auto mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, nullptr);

        EVP_DigestUpdate(mdctx, in.data(), in.size());
        EVP_DigestFinal_ex(mdctx, reinterpret_cast<unsigned char*>(hash.data()), &md_len);
        EVP_MD_CTX_free(mdctx);

        return hash;
    }
}