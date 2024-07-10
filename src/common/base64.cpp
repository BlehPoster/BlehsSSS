#include <common/base64.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace bleh::common {


    void Base64::base64_encode(const unsigned char* in, unsigned int in_size, unsigned char* out, unsigned int& out_size) {
        BIO* bio, * b64 = nullptr;
        BUF_MEM* buffer_ptr = nullptr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        BIO_write(bio, in, in_size);
        BIO_flush(bio);

        BIO_get_mem_ptr(bio, &buffer_ptr);
        BIO_set_close(bio, BIO_NOCLOSE);

        memcpy(out, buffer_ptr->data, buffer_ptr->length);
        out_size = static_cast<unsigned int>(buffer_ptr->length);

        BIO_free_all(bio);
    }

    void Base64::base64_decode(const unsigned char* in, unsigned int in_size, unsigned char* out, unsigned int& out_size) {
        BIO* bio, *b64 = nullptr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(in, static_cast<int>(in_size));
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        int decoded_size = BIO_read(bio, out, static_cast<int>(out_size));
        out_size = decoded_size;
        BIO_free_all(bio);
    }
}