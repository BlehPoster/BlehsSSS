#include <common/base64.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace bleh::common {

    std::string base64_encode(const std::string& in) {
        BIO* bio, *b64 = nullptr;
        BUF_MEM* buffer_ptr = nullptr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, in.data(), static_cast<int>(in.size()));
        BIO_flush(bio);

        BIO_get_mem_ptr(bio, &buffer_ptr);
        BIO_set_close(bio, BIO_NOCLOSE);

        auto out = std::string(buffer_ptr->data, buffer_ptr->length);
        BIO_free_all(bio);
        BUF_MEM_free(buffer_ptr);
        return out;
    }

    std::string base64_decode(const std::string& input) {
        BIO* bio, *b64 = nullptr;
        auto buffer = std::string(input.size(), 0);

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
        bio = BIO_push(b64, bio);

        int decoded_size = BIO_read(bio, const_cast<char*>(buffer.data()), static_cast<int>(input.size()));
        BIO_free_all(bio);

        buffer.resize(decoded_size);

        return buffer;
    }

    std::string Base64::encode(const std::string& data) {
        return base64_encode(data);
    }

    std::string Base64::decode(const std::string& data) {
        return base64_decode(data);
    }

}