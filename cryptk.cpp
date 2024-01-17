#include "cryptk.hpp"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

namespace cryptk
{
namespace rsa
{
enum PaddingMode
{
    PKCS1_PADDING      = 1,
    SSLV23_PADDING     = 2,
    NO_PADDING         = 3,
    PKCS1_OAEP_PADDING = 4,
    X931_PADDING       = 5,
    /* EVP_PKEY_ only */
    PKCS1_PSS_PADDING = 6,
};

namespace pub
{
// supported PaddingModes : RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING,
// RSA_NO_PADDING
std::string encrypt(std::string_view plaintext, std::string_view keystream, int paddingMode = PKCS1_OAEP_PADDING);
std::string decrypt(std::string_view cipertext, std::string_view keystream, int paddingMode = PKCS1_PADDING);

// supported PaddingModes : RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_SSLV23_PADDING,
// RSA_NO_PADDING
std::string encrypt2(std::string_view plaintext, std::string_view keyfile, int paddingMode = PKCS1_OAEP_PADDING);
std::string decrypt2(std::string_view cipertext, std::string_view keyfile, int paddingMode = PKCS1_PADDING);
}  // namespace pub

namespace pri
{
// supported PaddingModes : RSA_PKCS1_PADDING, RSA_X931_PADDING, RSA_NO_PADDING
std::string encrypt(std::string_view plaintext, std::string_view keystream, int paddingMode = PKCS1_PADDING);
std::string decrypt(std::string_view cipertext, std::string_view keystream, int paddingMode = PKCS1_OAEP_PADDING);

// supported PaddingModes : RSA_PKCS1_PADDING, RSA_X931_PADDING, RSA_NO_PADDING
std::string encrypt2(std::string_view plaintext, std::string_view keyfile, int paddingMode = PKCS1_PADDING);
std::string decrypt2(std::string_view cipertext, std::string_view keyfile, int paddingMode = PKCS1_OAEP_PADDING);
}  // namespace pri
}  // namespace rsa
}

namespace cryptk
{

namespace rsa
{
struct RSA_Key
{
    RSA* p_rsa;
    void* p_io;
};

typedef bool (*load_key_func)(const char* key, int /*length*/, RSA_Key* k);
typedef void (*compute_lens_func)(int paddingMode, int ilen, int& flen, int& olen);
typedef int (*RSA_crypto_func)(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding);
typedef void (*close_key_func)(RSA_Key* k);

static bool load_public_key_from_mem(const char* key, int length, RSA_Key* k)
{
    BIO* bio = NULL;
    if (length <= 0)
    {
        perror("The public key is empty!");
        return false;
    }

    if ((bio = BIO_new_mem_buf((char*)key, length)) == NULL)
    {
        perror("BIO_new_mem_buf failed!");
        return false;
    }

    k->p_io  = bio;
    k->p_rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (k->p_rsa == nullptr)
    {
        BIO_free_all(bio);
        return false;
    }

    return true;
}

static bool load_private_key_from_mem(const char* key, int length, RSA_Key* k)
{
    BIO* bio = NULL;
    if (length <= 0)
    {
        perror("The public key is empty!");
        return false;
    }

    if ((bio = BIO_new_mem_buf(key, length)) == NULL)
    {
        perror("BIO_new_mem_buf failed!");
        return false;
    }

    k->p_io  = bio;
    k->p_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if (k->p_rsa == nullptr)
    {
        BIO_free_all(bio);
        return false;
    }
    return true;
}

static bool load_public_key_from_file(const char* key, int /*length*/, RSA_Key* k)
{
    BIO* bio = NULL;
    if ((bio = BIO_new_file(key, "r")) == NULL)
    {
        perror("BIO_new_file failed!");
        return false;
    }

    k->p_io  = bio;
    k->p_rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (k->p_rsa == nullptr)
    {
        BIO_free_all(bio);
        return false;
    }

    return true;
}

static bool load_private_key_from_file(const char* key, int /*length*/, RSA_Key* k)
{
    BIO* bio = NULL;
    if ((bio = BIO_new_file(key, "r")) == NULL)
    {
        perror("BIO_new_file failed!");
        return false;
    }
    k->p_io  = bio;
    k->p_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if (k->p_rsa == nullptr)
    {
        BIO_free_all(bio);
        return false;
    }

    return true;
}

static void public_compute_lens(int paddingMode, int ilen, int& flen, int& olen)
{
    // pitfall: private encrypt supported PaddingModes: RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING,
    // RSA_SSLV23_PADDING, RSA_NO_PADDING
    const auto keylen = flen;
    switch (paddingMode)
    {
    case RSA_PKCS1_OAEP_PADDING:
        flen -= (2 * SHA_DIGEST_LENGTH + 2);  // pitfall: many blogs from internet said: it's 41,
                                              // actually, it must be 42, phpseclib does correct.
        break;
    case RSA_PKCS1_PADDING:
        // case RSA_SSLV23_PADDING:
        flen -= 11;
        break;
    case RSA_NO_PADDING:
        assert(ilen % flen == 0);
        break;
    }
    olen = ((ilen + flen - 1) / flen) * keylen;
}

static void private_compute_lens(int paddingMode, int ilen, int& flen, int& olen)
{
    // pitfall: private encrypt supported PaddingModes: RSA_PKCS1_PADDING, RSA_X931_PADDING,
    // RSA_NO_PADDING
    const auto keylen = flen;
    switch (paddingMode)
    {
    case RSA_PKCS1_PADDING:
        flen -= 11;
        break;
    case RSA_X931_PADDING:
        flen -= 2;
        break;
    case RSA_NO_PADDING:
        assert(ilen % flen == 0);
        break;
    };
    olen = ((ilen + flen - 1) / flen) * keylen;
}

static void close_keybio(RSA_Key* k)
{
    if (k->p_rsa != nullptr)
    {
        BIO_free_all((BIO*)k->p_io);
    }
}

struct encrypt_helper
{
    load_key_func load_key;
    compute_lens_func compute_lens;
    RSA_crypto_func crypto_func;
    close_key_func close_key;
};

struct decrypt_helper
{
    load_key_func load_key;
    RSA_crypto_func crypto_func;
    close_key_func close_key;
};

static std::string common_encrypt(std::string_view plaintext,
                                  std::string_view key,
                                  const encrypt_helper& helper,
                                  int paddingMode)
{
    RSA_Key k;

    int keylen = static_cast<int>(key.length());
    if (!helper.load_key(key.data(), keylen, &k))
        return "";

    int flen      = RSA_size(k.p_rsa);
    auto ilen     = plaintext.length();
    auto buffer   = (unsigned char*)malloc(flen);
    int iret      = -1, grab;
    size_t offset = 0;

#if defined(_DEBUG)
    const char* errormsg = nullptr;
    auto error_handler   = [](const char* str, size_t len, void* u) -> int {
        *((const char**)u) = str;
        return 0;
    };
#endif
    std::string result;

    int olen = ilen;
    helper.compute_lens(paddingMode, ilen, flen, olen);
    result.reserve(olen);

    do
    {
        grab = ilen - offset;
        if (grab > flen)
            grab = flen;
        iret = helper.crypto_func(grab, (const unsigned char*)plaintext.data() + offset, buffer, k.p_rsa, paddingMode);
        if (iret > 0)
        {
            result.insert(result.end(), buffer, buffer + iret);
            offset += grab;
        }
        else
        {
#if defined(_DEBUG)
            ERR_print_errors_cb(error_handler, &errormsg);
#endif
            break;
        }
    } while (offset < ilen);

    free(buffer);

    helper.close_key(&k);

    return result;
}

static std::string common_decrypt(std::string_view cipertext,
                                  std::string_view key,
                                  const decrypt_helper& helper,
                                  int paddingMode)
{
    RSA_Key k;

    int keylen = static_cast<int>(key.length());
    if (!helper.load_key(key.data(), keylen, &k))
        return "";

    std::string result;

#if defined(_DEBUG)
    const char* errormsg = nullptr;
    auto error_handler   = [](const char* str, size_t len, void* u) -> int {
        *((const char**)u) = str;
        return 0;
    };
#endif
    auto flen     = RSA_size(k.p_rsa);
    auto buffer   = (unsigned char*)malloc(flen);
    auto ilen     = cipertext.length();
    int iret      = -1;
    size_t offset = 0;
    do
    {
        iret = helper.crypto_func(flen, (const unsigned char*)cipertext.data() + offset, buffer, k.p_rsa, paddingMode);
        if (iret > 0)
        {
            result.insert(result.end(), buffer, buffer + iret);
            offset += flen;
        }
        else
        {
#if defined(_DEBUG)
            ERR_print_errors_cb(error_handler, &errormsg);
#endif
            break;
        }
    } while (offset < ilen);

    free(buffer);

    helper.close_key(&k);

    return result;
}

namespace pub
{
std::string encrypt(std::string_view plaintext, std::string_view key, int paddingMode)
{
    encrypt_helper helper = {load_public_key_from_mem, public_compute_lens, RSA_public_encrypt, close_keybio};
    return common_encrypt(plaintext, key, helper, paddingMode);
}
std::string decrypt(std::string_view ciphertext, std::string_view key, int paddingMode)
{
    decrypt_helper helper = {load_public_key_from_mem, RSA_public_decrypt, close_keybio};
    return common_decrypt(ciphertext, key, helper, paddingMode);
}

std::string encrypt2(std::string_view plaintext, std::string_view keyfile, int paddingMode)
{
    encrypt_helper helper = {load_public_key_from_file, public_compute_lens, RSA_public_encrypt, close_keybio};
    return common_encrypt(plaintext, keyfile, helper, paddingMode);
}
std::string decrypt2(std::string_view ciphertext, std::string_view keyfile, int paddingMode)
{
    decrypt_helper helper = {load_public_key_from_file, RSA_public_decrypt, close_keybio};
    return common_decrypt(ciphertext, keyfile, helper, paddingMode);
}
}  // namespace pub

namespace pri
{
std::string encrypt(std::string_view plaintext, std::string_view key, int paddingMode)
{
    encrypt_helper helper = {load_private_key_from_mem, private_compute_lens, (RSA_crypto_func)&RSA_private_encrypt,
                             close_keybio};
    return common_encrypt(plaintext, key, helper, paddingMode);
}
std::string decrypt(std::string_view ciphertext, std::string_view key, int paddingMode)
{
    decrypt_helper helper = {load_private_key_from_mem, RSA_private_decrypt, close_keybio};
    return common_decrypt(ciphertext, key, helper, paddingMode);
}

std::string encrypt2(std::string_view plaintext, std::string_view keyfile, int paddingMode)
{
    encrypt_helper helper = {load_private_key_from_file, private_compute_lens, (RSA_crypto_func)&RSA_private_encrypt,
                             close_keybio};
    return common_encrypt(plaintext, keyfile, helper, paddingMode);
}
std::string decrypt2(std::string_view ciphertext, std::string_view keyfile, int paddingMode)
{
    decrypt_helper helper = {load_private_key_from_file, RSA_private_decrypt, close_keybio};
    return common_decrypt(ciphertext, keyfile, helper, paddingMode);
}
}  // namespace pri
}  // namespace rsa
};  // namespace cryptk
