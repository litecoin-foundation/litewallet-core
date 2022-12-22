//
//  LWBIP38Key.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWBIP38Key_h
#define LWBIP38Key_h

#include "LWKey.h"

#ifdef __cplusplus
extern "C" {
#endif

// BIP38 is a method for encrypting private keys with a passphrase
// https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

int LWBIP38KeyIsValid(const char *bip38Key);

// decrypts a BIP38 key using the given passphrase and returns false if passphrase is incorrect
// passphrase must be unicode NFC normalized: http://www.unicode.org/reports/tr15/#Norm_Forms
int LWKeySetBIP38Key(LWKey *key, const char *bip38Key, const char *passphrase);

// generates an "intermediate code" for an EC multiply mode key
// salt should be 64bits of random data
// passphrase must be unicode NFC normalized
// returns number of bytes written to code including NULL terminator, or total codeLen needed if code is NULL
size_t LWKeyBIP38ItermediateCode(char *code, size_t codeLen, uint64_t salt, const char *passphrase);

// generates an "intermediate code" for an EC multiply mode key with a lot and sequence number
// lot must be less than 1048576, sequence must be less than 4096, and salt should be 32bits of random data
// passphrase must be unicode NFC normalized
// returns number of bytes written to code including NULL terminator, or total codeLen needed if code is NULL
size_t LWKeyBIP38ItermediateCodeLS(char *code, size_t codeLen, uint32_t lot, uint16_t sequence, uint32_t salt,
                                   const char *passphrase);

// generates a BIP38 key from an "intermediate code" and 24 bytes of cryptographically random data (seedb)
// compressed indicates if compressed pubKey format should be used for the bitcoin address
void LWKeySetBIP38ItermediateCode(LWKey *key, const char *code, const uint8_t *seedb, int compressed);

// encrypts key with passphrase
// passphrase must be unicode NFC normalized
// returns number of bytes written to bip38Key including NULL terminator or total bip38KeyLen needed if bip38Key is NULL
size_t LWKeyBIP38Key(LWKey *key, char *bip38Key, size_t bip38KeyLen, const char *passphrase);

#ifdef __cplusplus
}
#endif

#endif // LWBIP38Key_h
