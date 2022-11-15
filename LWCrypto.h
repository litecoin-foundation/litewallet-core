//
//  LWCrypto.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWCrypto_h
#define LWCrypto_h

#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// sha-1 - not recommended for cryptographic use
void LWSHA1(void *md20, const void *data, size_t len);

void LWSHA256(void *md32, const void *data, size_t len);

void LWSHA224(void *md28, const void *data, size_t len);

// double-sha-256 = sha-256(sha-256(x))
void LWSHA256_2(void *md32, const void *data, size_t len);

void LWSHA384(void *md48, const void *data, size_t len);

void LWSHA512(void *md64, const void *data, size_t len);

// ripemd-160: http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
void LWRMD160(void *md20, const void *data, size_t len);

// bitcoin hash-160 = ripemd-160(sha-256(x))
void LWHash160(void *md20, const void *data, size_t len);

// sha3-256: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
void LWSHA3_256(void *md32, const void *data, size_t len);

// keccak-256: https://keccak.team/files/Keccak-submission-3.pdf
void LWKeccak256(void *md32, const void *data, size_t len);

// md5 - for non-cryptographic use only
void LWMD5(void *md16, const void *data, size_t len);

// murmurHash3 (x86_32): https://code.google.com/p/smhasher/ - for non cryptographic use only
uint32_t LWMurmur3_32(const void *data, size_t len, uint32_t seed);

void LWHMAC(void *mac, void (*hash)(void *, const void *, size_t), size_t hashLen, const void *key, size_t keyLen,
            const void *data, size_t dataLen);

// hmac-drbg with no prediction resistance or additional input
// K and V must point to buffers of size hashLen, and ps (personalization string) may be NULL
// to generate additional drbg output, use K and V from the previous call, and set seed, nonce and ps to NULL
void LWHMACDRBG(void *out, size_t outLen, void *K, void *V, void (*hash)(void *, const void *, size_t), size_t hashLen,
                const void *seed, size_t seedLen, const void *nonce, size_t nonceLen, const void *ps, size_t psLen);

// poly1305 authenticator: https://tools.ietf.org/html/rfc7539
// NOTE: must use constant time mem comparison when verifying mac to defend against timing attacks
void LWPoly1305(void *mac16, const void *key32, const void *data, size_t len);

// chacha20 stream cypher: https://cr.yp.to/chacha.html
void LWChacha20(void *out, const void *key32, const void *iv8, const void *data, size_t len, uint64_t counter);
    
// chacha20-poly1305 authenticated encryption with associated data (AEAD): https://tools.ietf.org/html/rfc7539
size_t LWChacha20Poly1305AEADEncrypt(void *out, size_t outLen, const void *key32, const void *nonce12,
                                     const void *data, size_t dataLen, const void *ad, size_t adLen);

size_t LWChacha20Poly1305AEADDecrypt(void *out, size_t outLen, const void *key32, const void *nonce12,
                                     const void *data, size_t dataLen, const void *ad, size_t adLen);
    
void LWPBKDF2(void *dk, size_t dkLen, void (*hash)(void *, const void *, size_t), size_t hashLen,
              const void *pw, size_t pwLen, const void *salt, size_t saltLen, unsigned rounds);

// scrypt key derivation: http://www.tarsnap.com/scrypt.html
void LWScrypt(void *dk, size_t dkLen, const void *pw, size_t pwLen, const void *salt, size_t saltLen,
              unsigned n, unsigned r, unsigned p);

// zeros out memory in a way that can't be optimized out by the compiler
inline static void mem_clean(void *ptr, size_t len)
{
    void *(*volatile const memset_ptr)(void *, int, size_t) = memset;
    memset_ptr(ptr, 0, len);
}

#define var_clean(...) _var_clean(sizeof(*(_va_first(__VA_ARGS__))), __VA_ARGS__, NULL)
#define _va_first(first, ...) first

inline static void _var_clean(size_t size, ...)
{
    va_list args;
    va_start(args, size);
    for (void *ptr = va_arg(args, void *); ptr; ptr = va_arg(args, void *)) mem_clean(ptr, size);
    va_end(args);
}
    
#ifdef __cplusplus
}
#endif

#endif // BRCrypto_h
