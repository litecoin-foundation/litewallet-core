//
//  LWKey.c
//  https://github.com/litecoin-foundation/litewallet-core#readme#OpenSourceLink


#include "LWKey.h"
#include "LWAddress.h"
#include "LWBase58.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#define LITECOIN_PRIVKEY      176
#define LITECOIN_PRIVKEY_TEST 239

#if __BIG_ENDIAN__ || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||\
    __ARMEB__ || __THUMBEB__ || __AARCH64EB__ || __MIPSEB__
#define WORDS_BIGENDIAN        1
#endif
#define DETERMINISTIC          1
#define USE_BASIC_CONFIG       1
#define ENABLE_MODULE_RECOVERY 1

#pragma clang diagnostic push
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wconditional-uninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "secp256k1/src/basic-config.h"
#include "secp256k1/src/secp256k1.c"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop

static secp256k1_context *_ctx = NULL;
static pthread_once_t _ctx_once = PTHREAD_ONCE_INIT;

static void _ctx_init()
{
    _ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

// adds 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int LWSecp256k1ModAdd(UInt256 *a, const UInt256 *b)
{
    pthread_once(&_ctx_once, _ctx_init);
    return secp256k1_ec_privkey_tweak_add(_ctx, (unsigned char *)a, (const unsigned char *)b);
}

// multiplies 256bit big endian ints a and b (mod secp256k1 order) and stores the result in a
// returns true on success
int LWSecp256k1ModMul(UInt256 *a, const UInt256 *b)
{
    pthread_once(&_ctx_once, _ctx_init);
    return secp256k1_ec_privkey_tweak_mul(_ctx, (unsigned char *)a, (const unsigned char *)b);
}

// multiplies secp256k1 generator by 256bit big endian int i and stores the result in p
// returns true on success
int LWSecp256k1PointGen(LWECPoint *p, const UInt256 *i)
{
    secp256k1_pubkey pubkey;
    size_t pLen = sizeof(*p);
    
    pthread_once(&_ctx_once, _ctx_init);
    return (secp256k1_ec_pubkey_create(_ctx, &pubkey, (const unsigned char *)i) &&
            secp256k1_ec_pubkey_serialize(_ctx, (unsigned char *)p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// multiplies secp256k1 generator by 256bit big endian int i and adds the result to ec-point p
// returns true on success
int LWSecp256k1PointAdd(LWECPoint *p, const UInt256 *i)
{
    secp256k1_pubkey pubkey;
    size_t pLen = sizeof(*p);
    
    pthread_once(&_ctx_once, _ctx_init);
    return (secp256k1_ec_pubkey_parse(_ctx, &pubkey, (const unsigned char *)p, sizeof(*p)) &&
            secp256k1_ec_pubkey_tweak_add(_ctx, &pubkey, (const unsigned char *)i) &&
            secp256k1_ec_pubkey_serialize(_ctx, (unsigned char *)p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// multiplies secp256k1 ec-point p by 256bit big endian int i and stores the result in p
// returns true on success
int LWSecp256k1PointMul(LWECPoint *p, const UInt256 *i)
{
    secp256k1_pubkey pubkey;
    size_t pLen = sizeof(*p);
    
    pthread_once(&_ctx_once, _ctx_init);
    return (secp256k1_ec_pubkey_parse(_ctx, &pubkey, (const unsigned char *)p, sizeof(*p)) &&
            secp256k1_ec_pubkey_tweak_mul(_ctx, &pubkey, (const unsigned char *)i) &&
            secp256k1_ec_pubkey_serialize(_ctx, (unsigned char *)p, &pLen, &pubkey, SECP256K1_EC_COMPRESSED));
}

// returns true if privKey is a valid private key
// supported formats are wallet import format (WIF), mini private key format, or hex string
int LWPrivKeyIsValid(const char *privKey)
{
    uint8_t data[34];
    size_t dataLen, strLen;
    int r = 0;
    
    assert(privKey != NULL);

    dataLen = LWBase58CheckDecode(data, sizeof(data), privKey);
    strLen = strlen(privKey);
    
    if (dataLen == 33 || dataLen == 34) { // wallet import format: https://en.bitcoin.it/wiki/Wallet_import_format
#if LITECOIN_TESTNET
        r = (data[0] == LITECOIN_PRIVKEY_TEST);
#else
        r = (data[0] == LITECOIN_PRIVKEY);
#endif
    }
    else if ((strLen == 30 || strLen == 22) && privKey[0] == 'S') { // mini private key format
        char s[strLen + 2];
        
        strncpy(s, privKey, sizeof(s));
        s[sizeof(s) - 2] = '?';
        LWSHA256(data, s, sizeof(s) - 1);
        mem_clean(s, sizeof(s));
        r = (data[0] == 0);
    }
    else r = (strspn(privKey, "0123456789ABCDEFabcdef") == 64); // hex encoded key
    
    mem_clean(data, sizeof(data));
    return r;
}

// assigns secret to key and returns true on success
int LWKeySetSecret(LWKey *key, const UInt256 *secret, int compressed)
{
    assert(key != NULL);
    assert(secret != NULL);
    
    pthread_once(&_ctx_once, _ctx_init);
    LWKeyClean(key);
    key->secret = UInt256Get(secret);
    key->compressed = compressed;
    return secp256k1_ec_seckey_verify(_ctx, key->secret.u8);
}

// assigns privKey to key and returns true on success
// privKey must be wallet import format (WIF), mini private key format, or hex string
int LWKeySetPrivKey(LWKey *key, const char *privKey)
{
    size_t len = strlen(privKey);
    uint8_t data[34], version = LITECOIN_PRIVKEY;
    int r = 0;
    
#if LITECOIN_TESTNET
    version = LITECOIN_PRIVKEY_TEST;
#endif

    assert(key != NULL);
    assert(privKey != NULL);
    
    // mini private key format
    if ((len == 30 || len == 22) && privKey[0] == 'S') {
        if (! LWPrivKeyIsValid(privKey)) return 0;
        LWSHA256(data, privKey, strlen(privKey));
        r = LWKeySetSecret(key, (UInt256 *)data, 0);
    }
    else {
        len = LWBase58CheckDecode(data, sizeof(data), privKey);
        if (len == 0 || len == 28) len = LWBase58Decode(data, sizeof(data), privKey);

        if (len < sizeof(UInt256) || len > sizeof(UInt256) + 2) { // treat as hex string
            for (len = 0; privKey[len*2] && privKey[len*2 + 1] && len < sizeof(data); len++) {
                if (sscanf(&privKey[len*2], "%2hhx", &data[len]) != 1) break;
            }
        }

        if ((len == sizeof(UInt256) + 1 || len == sizeof(UInt256) + 2) && data[0] == version) {
            r = LWKeySetSecret(key, (UInt256 *)&data[1], (len == sizeof(UInt256) + 2));
        }
        else if (len == sizeof(UInt256)) {
            r = LWKeySetSecret(key, (UInt256 *)data, 0);
        }
    }

    mem_clean(data, sizeof(data));
    return r;
}

// assigns DER encoded pubKey to key and returns true on success
int LWKeySetPubKey(LWKey *key, const uint8_t *pubKey, size_t pkLen)
{
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    assert(pubKey != NULL);
    assert(pkLen == 33 || pkLen == 65);
    
    pthread_once(&_ctx_once, _ctx_init);
    LWKeyClean(key);
    memcpy(key->pubKey, pubKey, pkLen);
    key->compressed = (pkLen <= 33);
    return secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, pkLen);
}

// writes the WIF private key to privKey and returns the number of bytes writen, or pkLen needed if privKey is NULL
// returns 0 on failure
size_t LWKeyPrivKey(const LWKey *key, char *privKey, size_t pkLen)
{
    uint8_t data[34];

    assert(key != NULL);
    
    if (secp256k1_ec_seckey_verify(_ctx, key->secret.u8)) {
        data[0] = LITECOIN_PRIVKEY;
#if LITECOIN_TESTNET
        data[0] = LITECOIN_PRIVKEY_TEST;
#endif
        
        UInt256Set(&data[1], key->secret);
        if (key->compressed) data[33] = 0x01;
        pkLen = LWBase58CheckEncode(privKey, pkLen, data, (key->compressed) ? 34 : 33);
        mem_clean(data, sizeof(data));
    }
    else pkLen = 0;
    
    return pkLen;
}

// writes the DER encoded public key to pubKey and returns number of bytes written, or pkLen needed if pubKey is NULL
size_t LWKeyPubKey(LWKey *key, void *pubKey, size_t pkLen)
{
    static uint8_t empty[65]; // static vars initialize to zero
    size_t size = (key->compressed) ? 33 : 65;
    secp256k1_pubkey pk;

    assert(key != NULL);
    
    if (memcmp(key->pubKey, empty, size) == 0) {
        if (secp256k1_ec_pubkey_create(_ctx, &pk, key->secret.u8)) {
            secp256k1_ec_pubkey_serialize(_ctx, key->pubKey, &size, &pk,
                                          (key->compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
        }
        else size = 0;
    }

    if (pubKey && size <= pkLen) memcpy(pubKey, key->pubKey, size);
    return (! pubKey || size <= pkLen) ? size : 0;
}

// returns the ripemd160 hash of the sha256 hash of the public key
UInt160 LWKeyHash160(LWKey *key)
{
    UInt160 hash = UINT160_ZERO;
    size_t len;
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    len = LWKeyPubKey(key, NULL, 0);
    if (len > 0 && secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, len)) LWHash160(&hash, key->pubKey, len);
    return hash;
}

// writes the pay-to-pubkey-hash bitcoin address for key to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWKeyAddress(LWKey *key, char *addr, size_t addrLen)
{
    UInt160 hash;
    uint8_t data[21];

    assert(key != NULL);
    
    hash = LWKeyHash160(key);
    data[0] = LITECOIN_PUBKEY_ADDRESS;
#if LITECOIN_TESTNET
    data[0] = LITECOIN_PUBKEY_ADDRESS_TEST;
#endif
    UInt160Set(&data[1], hash);

    if (! UInt160IsZero(hash)) {
        addrLen = LWBase58CheckEncode(addr, addrLen, data, sizeof(data));
    }
    else addrLen = 0;
    
    return addrLen;
}

// signs md with key and writes signature to sig
// returns the number of bytes written, or sigLen needed if sig is NULL
// returns 0 on failure
size_t LWKeySign(const LWKey *key, void *sig, size_t sigLen, UInt256 md)
{
    secp256k1_ecdsa_signature s;
    
    assert(key != NULL);
    
    if (secp256k1_ecdsa_sign(_ctx, &s, md.u8, key->secret.u8, secp256k1_nonce_function_rfc6979, NULL)) {
        if (! secp256k1_ecdsa_signature_serialize_der(_ctx, sig, &sigLen, &s)) sigLen = 0;
    }
    else sigLen = 0;
    
    return sigLen;
}

// returns true if the signature for md is verified to have been made by key
int LWKeyVerify(LWKey *key, UInt256 md, const void *sig, size_t sigLen)
{
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature s;
    size_t len;
    int r = 0;
    
    assert(key != NULL);
    assert(sig != NULL || sigLen == 0);
    assert(sigLen > 0);
    
    len = LWKeyPubKey(key, NULL, 0);
    
    if (len > 0 && secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, len) &&
        secp256k1_ecdsa_signature_parse_der(_ctx, &s, sig, sigLen)) {
        if (secp256k1_ecdsa_verify(_ctx, &s, md.u8, &pk) == 1) r = 1; // success is 1, all other values are fail
    }
    
    return r;
}

// wipes key material from key
void LWKeyClean(LWKey *key)
{
    assert(key != NULL);
    var_clean(key);
}

// Pieter Wuille's compact signature encoding used for bitcoin message signing
// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
size_t LWKeyCompactSign(const LWKey *key, void *compactSig, size_t sigLen, UInt256 md)
{
    size_t r = 0;
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature s;

    assert(key != NULL);
    assert(sigLen >= 65 || compactSig == NULL);

    if (! UInt256IsZero(key->secret)) { // can't sign with a public key
        if (compactSig && sigLen >= 65 &&
            secp256k1_ecdsa_sign_recoverable(_ctx, &s, md.u8, key->secret.u8, secp256k1_nonce_function_rfc6979, NULL) &&
            secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx, (uint8_t *)compactSig + 1, &recid, &s)) {
            ((uint8_t *)compactSig)[0] = 27 + recid + (key->compressed ? 4 : 0);
            r = 65;
        }
        else if (! compactSig) r = 65;
    }
    
    return r;
}

// assigns pubKey recovered from compactSig to key and returns true on success
int LWKeyRecoverPubKey(LWKey *key, UInt256 md, const void *compactSig, size_t sigLen)
{
    int r = 0, compressed = 0, recid = 0;
    uint8_t pubKey[65];
    size_t len = sizeof(pubKey);
    secp256k1_ecdsa_recoverable_signature s;
    secp256k1_pubkey pk;
    
    assert(key != NULL);
    assert(compactSig != NULL);
    assert(sigLen == 65);
    
    if (sigLen == 65) {
        if (((uint8_t *)compactSig)[0] - 27 >= 4) compressed = 1;
        recid = (((uint8_t *)compactSig)[0] - 27) % 4;
        
        if (secp256k1_ecdsa_recoverable_signature_parse_compact(_ctx, &s, (const uint8_t *)compactSig + 1, recid) &&
            secp256k1_ecdsa_recover(_ctx, &pk, &s, md.u8) &&
            secp256k1_ec_pubkey_serialize(_ctx, pubKey, &len, &pk,
                                          (compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))) {
            r = LWKeySetPubKey(key, pubKey, len);
        }
    }

    return r;
}
