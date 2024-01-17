/*
* The wrapper of openssl RSA encrypt/decrypt
* verify easy to use
* Note: The key must be PKCS#8 PEM format, refer online RSA key generators:
*    - https://cryptotools.net/rsagen
*    - http://www.metools.info/code/c80.html
*/
#pragma once

#include <string>
#include <string_view>

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
