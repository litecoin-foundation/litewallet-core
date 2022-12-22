//
//  BRBIP32Sequence.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md


#ifndef LWBIP32Sequence_h
#define LWBIP32Sequence_h

#include "LWKey.h"
#include "LWInt.h"
#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

#define BIP32_HARD                  0x80000000

#define SEQUENCE_GAP_LIMIT_EXTERNAL 10
#define SEQUENCE_GAP_LIMIT_INTERNAL 5
#define SEQUENCE_EXTERNAL_CHAIN     0
#define SEQUENCE_INTERNAL_CHAIN     1

typedef struct {
    uint32_t fingerPrint;
    UInt256 chainCode;
    uint8_t pubKey[33];
} LWMasterPubKey;

#define LW_MASTER_PUBKEY_NONE ((LWMasterPubKey) { 0, UINT256_ZERO, \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } })

// returns the master public key for the default BIP32 wallet layout - derivation path N(m/0H)
LWMasterPubKey LWBIP32MasterPubKey(const void *seed, size_t seedLen);

// writes the public key for path N(m/0H/chain/index) to pubKey
// returns number of bytes written, or pubKeyLen needed if pubKey is NULL
size_t LWBIP32PubKey(uint8_t *pubKey, size_t pubKeyLen, LWMasterPubKey mpk, uint32_t chain, uint32_t index);

// sets the private key for path m/0H/chain/index to key
void LWBIP32PrivKey(LWKey *key, const void *seed, size_t seedLen, uint32_t chain, uint32_t index);

// sets the private key for path m/0H/chain/index to each element in keys
void LWBIP32PrivKeyList(LWKey keys[], size_t keysCount, const void *seed, size_t seedLen, uint32_t chain,
                        const uint32_t indexes[]);
    
// sets the private key for the specified path to key
// depth is the number of arguments used to specify the path
void LWBIP32PrivKeyPath(LWKey *key, const void *seed, size_t seedLen, int depth, ...);

// sets the private key for the path specified by vlist to key
// depth is the number of arguments in vlist
void LWBIP32vPrivKeyPath(LWKey *key, const void *seed, size_t seedLen, int depth, va_list vlist);

// writes the base58check encoded serialized master private key (xprv) to str
// returns number of bytes written including NULL terminator, or strLen needed if str is NULL
size_t LWBIP32SerializeMasterPrivKey(char *str, size_t strLen, const void *seed, size_t seedLen);

// writes a master private key to seed given a base58check encoded serialized master private key (xprv)
// returns number of bytes written, or seedLen needed if seed is NULL
size_t LWBIP32ParseMasterPrivKey(void *seed, size_t seedLen, const char *str);

// writes the base58check encoded serialized master public key (xpub) to str
// returns number of bytes written including NULL terminator, or strLen needed if str is NULL
size_t LWBIP32SerializeMasterPubKey(char *str, size_t strLen, LWMasterPubKey mpk);

// returns a master public key give a base58check encoded serialized master public key (xpub)
LWMasterPubKey LWBIP32ParseMasterPubKey(const char *str);

// key used for authenticated API calls, i.e. bitauth: https://github.com/bitpay/bitauth - path m/1H/0
void LWBIP32APIAuthKey(LWKey *key, const void *seed, size_t seedLen);

#ifdef __cplusplus
}
#endif

#endif // LWBIP32Sequence_h
