#include <common/sha.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

namespace bleh::common {

    void Sha2::sha256(const unsigned char* in, unsigned int in_size, unsigned char* out, unsigned int& out_size) {
        auto md = EVP_sha256();
        auto mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, nullptr);

        EVP_DigestUpdate(mdctx, in, in_size);
        EVP_DigestFinal_ex(mdctx, out, &out_size);
        EVP_MD_CTX_free(mdctx);
    }
}