//
//  LWBase58.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md


#ifndef LWBase58_h
#define LWBase58_h

#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// base58 and base58check encoding: https://en.bitcoin.it/wiki/Base58Check_encoding

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t LWBase58Encode(char *str, size_t strLen, const uint8_t *data, size_t dataLen);

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t LWBase58Decode(uint8_t *data, size_t dataLen, const char *str);

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t LWBase58CheckEncode(char *str, size_t strLen, const uint8_t *data, size_t dataLen);

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t LWBase58CheckDecode(uint8_t *data, size_t dataLen, const char *str);

#ifdef __cplusplus
}
#endif

#endif // LWBase58_h
