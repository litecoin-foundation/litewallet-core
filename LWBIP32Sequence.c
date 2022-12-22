//
//  LWBIP32Sequence.c
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#include "LWBIP32Sequence.h"
#include "LWCrypto.h"
#include "LWBase58.h"
#include <string.h>
#include <assert.h>

#define BIP32_SEED_KEY "Bitcoin seed"
#define BIP32_XPRV     "\x04\x88\xAD\xE4"
#define BIP32_XPUB     "\x04\x88\xB2\x1E"

// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

// Private parent key -> private child key
//
// CKDpriv((kpar, cpar), i) -> (ki, ci) computes a child extended private key from the parent extended private key:
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
//       (Note: The 0x00 pads the private key to make it 33 bytes long.)
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key ki is parse256(IL) + kpar (mod n).
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i
//   (Note: this has probability lower than 1 in 2^127.)
//
static void _CKDpriv(UInt256 *k, UInt256 *c, uint32_t i)
{
    uint8_t buf[sizeof(LWECPoint) + sizeof(i)];
    UInt512 I;
    
    if (i & BIP32_HARD) {
        buf[0] = 0;
        UInt256Set(&buf[1], *k);
    }
    else LWSecp256k1PointGen((LWECPoint *)buf, k);
    
    UInt32SetBE(&buf[sizeof(LWECPoint)], i);
    
    LWHMAC(&I, LWSHA512, sizeof(UInt512), c, sizeof(*c), buf, sizeof(buf)); // I = HMAC-SHA512(c, k|P(k) || i)
    
    LWSecp256k1ModAdd(k, (UInt256 *)&I); // k = IL + k (mod n)
    *c = *(UInt256 *)&I.u8[sizeof(UInt256)]; // c = IR
    
    var_clean(&I);
    mem_clean(buf, sizeof(buf));
}

// Public parent key -> public child key
//
// CKDpub((Kpar, cpar), i) -> (Ki, ci) computes a child extended public key from the parent extended public key.
// It is only defined for non-hardened child keys.
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): return failure
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key Ki is point(parse256(IL)) + Kpar.
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with
//   the next value for i.
//
static void _CKDpub(LWECPoint *K, UInt256 *c, uint32_t i)
{
    uint8_t buf[sizeof(*K) + sizeof(i)];
    UInt512 I;

    if ((i & BIP32_HARD) != BIP32_HARD) { // can't derive private child key from public parent key
        *(LWECPoint *)buf = *K;
        UInt32SetBE(&buf[sizeof(*K)], i);
    
        LWHMAC(&I, LWSHA512, sizeof(UInt512), c, sizeof(*c), buf, sizeof(buf)); // I = HMAC-SHA512(c, P(K) || i)
        
        *c = *(UInt256 *)&I.u8[sizeof(UInt256)]; // c = IR
        LWSecp256k1PointAdd(K, (UInt256 *)&I); // K = P(IL) + K

        var_clean(&I);
        mem_clean(buf, sizeof(buf));
    }
}

// returns the master public key for the default BIP32 wallet layout - derivation path N(m/0H)
LWMasterPubKey LWBIP32MasterPubKey(const void *seed, size_t seedLen)
{
    LWMasterPubKey mpk = LW_MASTER_PUBKEY_NONE;
    UInt512 I;
    UInt256 secret, chain;
    LWKey key;

    assert(seed != NULL || seedLen == 0);
    
    if (seed || seedLen == 0) {
        LWHMAC(&I, LWSHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed, seedLen);
        secret = *(UInt256 *)&I;
        chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
        var_clean(&I);
    
        LWKeySetSecret(&key, &secret, 1);
        mpk.fingerPrint = LWKeyHash160(&key).u32[0];
        
        _CKDpriv(&secret, &chain, 0 | BIP32_HARD); // path m/0H
    
        mpk.chainCode = chain;
        LWKeySetSecret(&key, &secret, 1);
        var_clean(&secret, &chain);
        LWKeyPubKey(&key, &mpk.pubKey, sizeof(mpk.pubKey)); // path N(m/0H)
        LWKeyClean(&key);
    }
    
    return mpk;
}

// writes the public key for path N(m/0H/chain/index) to pubKey
// returns number of bytes written, or pubKeyLen needed if pubKey is NULL
size_t LWBIP32PubKey(uint8_t *pubKey, size_t pubKeyLen, LWMasterPubKey mpk, uint32_t chain, uint32_t index)
{
    UInt256 chainCode = mpk.chainCode;
    
    assert(memcmp(&mpk, &LW_MASTER_PUBKEY_NONE, sizeof(mpk)) != 0);
    
    if (pubKey && sizeof(LWECPoint) <= pubKeyLen) {
        *(LWECPoint *)pubKey = *(LWECPoint *)mpk.pubKey;

        _CKDpub((LWECPoint *)pubKey, &chainCode, chain); // path N(m/0H/chain)
        _CKDpub((LWECPoint *)pubKey, &chainCode, index); // index'th key in chain
        var_clean(&chainCode);
    }
    
    return (! pubKey || sizeof(LWECPoint) <= pubKeyLen) ? sizeof(LWECPoint) : 0;
}

// sets the private key for path m/0H/chain/index to key
void LWBIP32PrivKey(LWKey *key, const void *seed, size_t seedLen, uint32_t chain, uint32_t index)
{
    LWBIP32PrivKeyPath(key, seed, seedLen, 3, 0 | BIP32_HARD, chain, index);
}

// sets the private key for path m/0H/chain/index to each element in keys
void LWBIP32PrivKeyList(LWKey keys[], size_t keysCount, const void *seed, size_t seedLen, uint32_t chain,
                        const uint32_t indexes[])
{
    UInt512 I;
    UInt256 secret, chainCode, s, c;
    
    assert(keys != NULL || keysCount == 0);
    assert(seed != NULL || seedLen == 0);
    assert(indexes != NULL || keysCount == 0);
    
    if (keys && keysCount > 0 && (seed || seedLen == 0) && indexes) {
        LWHMAC(&I, LWSHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed, seedLen);
        secret = *(UInt256 *)&I;
        chainCode = *(UInt256 *)&I.u8[sizeof(UInt256)];
        var_clean(&I);

        _CKDpriv(&secret, &chainCode, 0 | BIP32_HARD); // path m/0H
        _CKDpriv(&secret, &chainCode, chain); // path m/0H/chain
    
        for (size_t i = 0; i < keysCount; i++) {
            s = secret;
            c = chainCode;
            _CKDpriv(&s, &c, indexes[i]); // index'th key in chain
            LWKeySetSecret(&keys[i], &s, 1);
        }
        
        var_clean(&secret, &chainCode, &c, &s);
    }
}

// sets the private key for the specified path to key
// depth is the number of arguments used to specify the path
void LWBIP32PrivKeyPath(LWKey *key, const void *seed, size_t seedLen, int depth, ...)
{
    va_list ap;

    va_start(ap, depth);
    LWBIP32vPrivKeyPath(key, seed, seedLen, depth, ap);
    va_end(ap);
}

// sets the private key for the path specified by vlist to key
// depth is the number of arguments in vlist
void LWBIP32vPrivKeyPath(LWKey *key, const void *seed, size_t seedLen, int depth, va_list vlist)
{
    UInt512 I;
    UInt256 secret, chainCode;
    
    assert(key != NULL);
    assert(seed != NULL || seedLen == 0);
    assert(depth >= 0);
    
    if (key && (seed || seedLen == 0)) {
        LWHMAC(&I, LWSHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed, seedLen);
        secret = *(UInt256 *)&I;
        chainCode = *(UInt256 *)&I.u8[sizeof(UInt256)];
        var_clean(&I);
     
        for (int i = 0; i < depth; i++) {
            _CKDpriv(&secret, &chainCode, va_arg(vlist, uint32_t));
        }
        
        LWKeySetSecret(key, &secret, 1);
        var_clean(&secret, &chainCode);
    }
}

// writes the base58check encoded serialized master private key (xprv) to str
// returns number of bytes written including NULL terminator, or strLen needed if str is NULL
size_t LWBIP32SerializeMasterPrivKey(char *str, size_t strLen, const void *seed, size_t seedLen)
{
    // TODO: XXX implement
    return 0;
}

// writes a master private key to seed given a base58check encoded serialized master private key (xprv)
// returns number of bytes written, or seedLen needed if seed is NULL
size_t LWBIP32ParseMasterPrivKey(void *seed, size_t seedLen, const char *str)
{
    // TODO: XXX implement
    return 0;
}

// writes the base58check encoded serialized master public key (xpub) to str
// returns number of bytes written including NULL terminator, or strLen needed if str is NULL
size_t LWBIP32SerializeMasterPubKey(char *str, size_t strLen, LWMasterPubKey mpk)
{
    // TODO: XXX implement
    return 0;
}

// returns a master public key give a base58check encoded serialized master public key (xpub)
LWMasterPubKey LWBIP32ParseMasterPubKey(const char *str)
{
    // TODO: XXX implement
    return LW_MASTER_PUBKEY_NONE;
}

// key used for authenticated API calls, i.e. bitauth: https://github.com/bitpay/bitauth - path m/1H/0
void LWBIP32APIAuthKey(LWKey *key, const void *seed, size_t seedLen)
{
    LWBIP32PrivKeyPath(key, seed, seedLen, 2, 1 | BIP32_HARD, 0);
}

