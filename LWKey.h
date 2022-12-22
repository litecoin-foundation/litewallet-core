//
//  LWKey.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md


#ifndef LWKey_h
#define LWKey_h

#include "LWInt.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t p[33];
} LWECPoint;

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int LWSecp256k1ModAdd(UInt256 *a, const UInt256 *b);

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int LWSecp256k1ModMul(UInt256 *a, const UInt256 *b);

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in p
// returns true on success
int LWSecp256k1PointGen(LWECPoint *p, const UInt256 *i);

// multiplies secp256k1 generator by 256bit big endian int i and adds the result to ec-point p
// returns true on success
int LWSecp256k1PointAdd(LWECPoint *p, const UInt256 *i);

// multiplies secp256k1 ec-point p by 256bit big endian int i and stores the result in p
// returns true on success
int LWSecp256k1PointMul(LWECPoint *p, const UInt256 *i);

// returns true if privKey is a valid private key
// supported formats are wallet import format (WIF), mini private key format, or hex string
int LWPrivKeyIsValid(const char *privKey);

typedef struct {
    UInt256 secret;
    uint8_t pubKey[65];
    int compressed;
} LWKey;

// assigns secret to key and returns true on success
int LWKeySetSecret(LWKey *key, const UInt256 *secret, int compressed);

// assigns privKey to key and returns true on success
// privKey must be wallet import format (WIF), mini private key format, or hex string
int LWKeySetPrivKey(LWKey *key, const char *privKey);

// assigns DER encoded pubKey to key and returns true on success
int LWKeySetPubKey(LWKey *key, const uint8_t *pubKey, size_t pkLen);

// writes the WIF private key to privKey and returns the number of bytes writen, or pkLen needed if privKey is NULL
// returns 0 on failure
size_t LWKeyPrivKey(const LWKey *key, char *privKey, size_t pkLen);

// writes the DER encoded public key to pubKey and returns number of bytes written, or pkLen needed if pubKey is NULL
size_t LWKeyPubKey(LWKey *key, void *pubKey, size_t pkLen);

// returns the ripemd160 hash of the sha256 hash of the public key, or UINT160_ZERO on error
UInt160 LWKeyHash160(LWKey *key);

// writes the pay-to-pubkey-hash bitcoin address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWKeyAddress(LWKey *key, char *addr, size_t addrLen);

// signs md with key and writes signature to sig
// returns the number of bytes written, or sigLen needed if sig is NULL
// returns 0 on failure
size_t LWKeySign(const LWKey *key, void *sig, size_t sigLen, UInt256 md);

// returns true if the signature for md is verified to have been made by key
int LWKeyVerify(LWKey *key, UInt256 md, const void *sig, size_t sigLen);

// wipes key material from key
void LWKeyClean(LWKey *key);

// Pieter Wuille's compact signature encoding used for bitcoin message signing
// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
size_t LWKeyCompactSign(const LWKey *key, void *compactSig, size_t sigLen, UInt256 md);

// assigns pubKey recovered from compactSig to key and returns true on success
int LWKeyRecoverPubKey(LWKey *key, UInt256 md, const void *compactSig, size_t sigLen);

#ifdef __cplusplus
}
#endif

#endif // LWKey_h
