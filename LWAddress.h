//
// LWAddress.h
// https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWAddress_h
#define LWAddress_h

#include "LWCrypto.h"
#include <string.h>
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#if LITECOIN_TESTNET
#pragma message "testnet build"
#endif

// Litecoin address prefixes
#define LITECOIN_PUBKEY_ADDRESS      48     // P2PKH L-address 0x30
#define LITECOIN_SCRIPT_ADDRESS      50     // P2SH M-address 0x32
#define LITECOIN_PUBKEY_ADDRESS_TEST 111    // P2PKH m- or n-address 0x6f
#define LITECOIN_SCRIPT_ADDRESS_TEST 58     // P2SH new Q-address 0x3a

// bitcoin script opcodes: https://en.bitcoin.it/wiki/Script#Constants
#define OP_0           0x00
#define OP_PUSHDATA1   0x4c
#define OP_PUSHDATA2   0x4d
#define OP_PUSHDATA4   0x4e
#define OP_1NEGATE     0x4f
#define OP_1           0x51
#define OP_16          0x60
#define OP_DUP         0x76
#define OP_EQUAL       0x87
#define OP_EQUALVERIFY 0x88
#define OP_HASH160     0xa9
#define OP_CHECKSIG    0xac

// reads a varint from buf and stores its length in intLen if intLen is non-NULL
// returns the varint value
uint64_t LWVarInt(const uint8_t *buf, size_t bufLen, size_t *intLen);

// writes i to buf as a varint and returns the number of bytes written, or bufLen needed if buf is NULL
size_t LWVarIntSet(uint8_t *buf, size_t bufLen, uint64_t i);

// returns the number of bytes needed to encode i as a varint
size_t LWVarIntSize(uint64_t i);

// parses script and writes an array of pointers to the script elements (opcodes and data pushes) to elems
// returns the number of elements written, or elemsCount needed if elems is NULL
size_t LWScriptElements(const uint8_t *elems[], size_t elemsCount, const uint8_t *script, size_t scriptLen);

// given a data push script element, returns a pointer to the start of the data and writes its length to dataLen
const uint8_t *LWScriptData(const uint8_t *elem, size_t *dataLen);

// writes a data push script element to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t LWScriptPushData(uint8_t *script, size_t scriptLen, const uint8_t *data, size_t dataLen);

typedef struct {
    char s[75];
} LWAddress;

#define LW_ADDRESS_NONE ((LWAddress) { "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"\
                                       "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" })

// writes the bitcoin address for a scriptPubKey to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWAddressFromScriptPubKey(char *addr, size_t addrLen, const uint8_t *script, size_t scriptLen);

// writes the bitcoin address for a scriptSig to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWAddressFromScriptSig(char *addr, size_t addrLen, const uint8_t *script, size_t scriptLen);

// writes the bitcoin address for a witness to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWAddressFromWitness(char *addr, size_t addrLen, const uint8_t *witness, size_t witLen);

// writes the scriptPubKey for addr to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t LWAddressScriptPubKey(uint8_t *script, size_t scriptLen, const char *addr);

// returns true if addr is a valid bitcoin address
int LWAddressIsValid(const char *addr);

// writes the 20 byte hash160 of addr to md20 and returns true on success
int LWAddressHash160(void *md20, const char *addr);

// returns a hash value for addr suitable for use in a hashtable
inline static size_t LWAddressHash(const void *addr)
{
    return LWMurmur3_32(addr, strlen((const char *)addr), 0);
}

// true if addr and otherAddr are equal
inline static int LWAddressEq(const void *addr, const void *otherAddr)
{
    return (addr == otherAddr ||
            strncmp((const char *)addr, (const char *)otherAddr, sizeof(LWAddress)) == 0);
}

#ifdef __cplusplus
}
#endif

#endif // LWAddress_h
