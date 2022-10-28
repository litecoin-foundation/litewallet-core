//
// LWAddress.c
// https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#include "LWAddress.h"
#include "LWBase58.h"
#include "LWBech32.h"
#include "LWInt.h"
#include <inttypes.h>
#include <assert.h>

#define VAR_INT16_HEADER  0xfd
#define VAR_INT32_HEADER  0xfe
#define VAR_INT64_HEADER  0xff
#define MAX_SCRIPT_LENGTH 0x100 // scripts over this size will not be parsed for an address

// reads a varint from buf and stores its length in intLen if intLen is non-NULL
// returns the varint value
uint64_t LWVarInt(const uint8_t *buf, size_t bufLen, size_t *intLen)
{
    uint64_t r = 0;
    uint8_t h = (buf && sizeof(uint8_t) <= bufLen) ? *buf : 0;
    
    switch (h) {
        case VAR_INT16_HEADER:
            if (intLen) *intLen = sizeof(h) + sizeof(uint16_t);
            r = (buf && sizeof(h) + sizeof(uint16_t) <= bufLen) ? UInt16GetLE(&buf[sizeof(h)]) : 0;
            break;
            
        case VAR_INT32_HEADER:
            if (intLen) *intLen = sizeof(h) + sizeof(uint32_t);
            r = (buf && sizeof(h) + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[sizeof(h)]) : 0;
            break;
            
        case VAR_INT64_HEADER:
            if (intLen) *intLen = sizeof(h) + sizeof(uint64_t);
            r = (buf && sizeof(h) + sizeof(uint64_t) <= bufLen) ? UInt64GetLE(&buf[sizeof(h)]) : 0;
            break;
            
        default:
            if (intLen) *intLen = sizeof(h);
            r = h;
            break;
    }
    
    return r;
}

// writes i to buf as a varint and returns the number of bytes written, or bufLen needed if buf is NULL
size_t LWVarIntSet(uint8_t *buf, size_t bufLen, uint64_t i)
{
    size_t r = 0;
    
    if (i < VAR_INT16_HEADER) {
        if (buf && sizeof(uint8_t) <= bufLen) *buf = (uint8_t)i;
        r = (! buf || sizeof(uint8_t) <= bufLen) ? sizeof(uint8_t) : 0;
    }
    else if (i <= UINT16_MAX) {
        if (buf && sizeof(uint8_t) + sizeof(uint16_t) <= bufLen) {
            *buf = VAR_INT16_HEADER;
            UInt16SetLE(&buf[sizeof(uint8_t)], (uint16_t)i);
        }
        
        r = (! buf || sizeof(uint8_t) + sizeof(uint16_t) <= bufLen) ? sizeof(uint8_t) + sizeof(uint16_t) : 0;
    }
    else if (i <= UINT32_MAX) {
        if (buf && sizeof(uint8_t) + sizeof(uint32_t) <= bufLen) {
            *buf = VAR_INT32_HEADER;
            UInt32SetLE(&buf[sizeof(uint8_t)], (uint32_t)i);
        }
        
        r = (! buf || sizeof(uint8_t) + sizeof(uint32_t) <= bufLen) ? sizeof(uint8_t) + sizeof(uint32_t) : 0;
    }
    else {
        if (buf && sizeof(uint8_t) + sizeof(uint64_t) <= bufLen) {
            *buf = VAR_INT64_HEADER;
            UInt64SetLE(&buf[sizeof(uint8_t)], i);
        }
        
        r = (! buf || sizeof(uint8_t) + sizeof(uint64_t) <= bufLen) ? sizeof(uint8_t) + sizeof(uint64_t) : 0;
    }
    
    return r;
}

// returns the number of bytes needed to encode i as a varint
size_t LWVarIntSize(uint64_t i)
{
    return LWVarIntSet(NULL, 0, i);
}

// parses script and writes an array of pointers to the script elements (opcodes and data pushes) to elems
// returns the number of elements written, or elemsCount needed if elems is NULL
size_t LWScriptElements(const uint8_t *elems[], size_t elemsCount, const uint8_t *script, size_t scriptLen)
{
    size_t off = 0, i = 0, len = 0;
    
    assert(script != NULL || scriptLen == 0);
    
    while (script && off < scriptLen) {
        if (elems && i < elemsCount) elems[i] = &script[off];
        
        switch (script[off]) {
            case OP_PUSHDATA1:
                off++;
                if (off + sizeof(uint8_t) <= scriptLen) len = script[off];
                off += sizeof(uint8_t);
                break;
                
            case OP_PUSHDATA2:
                off++;
                if (off + sizeof(uint16_t) <= scriptLen) len = UInt16GetLE(&script[off]);
                off += sizeof(uint16_t);
                break;
                
            case OP_PUSHDATA4:
                off++;
                if (off + sizeof(uint32_t) <= scriptLen) len = UInt32GetLE(&script[off]);
                off += sizeof(uint32_t);
                break;
                
            default:
                len = (script[off] > OP_PUSHDATA4) ? 0 : script[off];
                off++;
                break;
        }
        
        off += len;
        i++;
    }
        
    return ((! elems || i <= elemsCount) && off == scriptLen) ? i : 0;
}

// given a data push script element, returns a pointer to the start of the data and writes its length to dataLen
const uint8_t *LWScriptData(const uint8_t *elem, size_t *dataLen)
{
    assert(elem != NULL);
    assert(dataLen != NULL);
    if (! elem || ! dataLen) return NULL;
    
    switch (*elem) {
        case OP_PUSHDATA1:
            elem++;
            *dataLen = *elem;
            elem += sizeof(uint8_t);
            break;
            
        case OP_PUSHDATA2:
            elem++;
            *dataLen = UInt16GetLE(elem);
            elem += sizeof(uint16_t);
            break;
            
        case OP_PUSHDATA4:
            elem++;
            *dataLen = UInt32GetLE(elem);
            elem += sizeof(uint32_t);
            break;
            
        default:
            *dataLen = (*elem > OP_PUSHDATA4) ? 0 : *elem;
            elem++;
            break;
    }
    
    return (*dataLen > 0) ? elem : NULL;
}

// writes a data push script element to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t LWScriptPushData(uint8_t *script, size_t scriptLen, const uint8_t *data, size_t dataLen)
{
    size_t len = dataLen;

    assert(data != NULL || dataLen == 0);
    if (data == NULL && dataLen != 0) return 0;
    
    if (dataLen < OP_PUSHDATA1) {
        len += 1;
        if (script && len <= scriptLen) script[0] = dataLen;
    }
    else if (dataLen < UINT8_MAX) {
        len += 1 + sizeof(uint8_t);
        
        if (script && len <= scriptLen) {
            script[0] = OP_PUSHDATA1;
            script[1] = dataLen;
        }
    }
    else if (dataLen < UINT16_MAX) {
        len += 1 + sizeof(uint16_t);
        
        if (script && len <= scriptLen) {
            script[0] = OP_PUSHDATA2;
            UInt16SetLE(&script[1], dataLen);
        }
    }
    else {
        len += 1 + sizeof(uint32_t);
        
        if (script && len <= scriptLen) {
            script[0] = OP_PUSHDATA4;
            UInt32SetLE(&script[1], (uint32_t)dataLen);
        }
    }
    
    if (script && len <= scriptLen) memcpy(script + len - dataLen, data, dataLen);
    return (! script || len <= scriptLen) ? len : 0;
}

// NOTE: It's important here to be permissive with scriptSig (spends) and strict with scriptPubKey (receives). If we
// miss a receive transaction, only that transaction's funds are missed, however if we accept a receive transaction that
// we are unable to correctly sign later, then the entire wallet balance after that point would become stuck with the
// current coin selection code

// writes the bitcoin address for a scriptPubKey to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWAddressFromScriptPubKey(char *addr, size_t addrLen, const uint8_t *script, size_t scriptLen)
{
    assert(script != NULL || scriptLen == 0);
    if (! script || scriptLen == 0 || scriptLen > MAX_SCRIPT_LENGTH) return 0;
    
    uint8_t data[21];
    const uint8_t *d, *elems[LWScriptElements(NULL, 0, script, scriptLen)];
    char a[91];
    size_t r = 0, l = 0, count = LWScriptElements(elems, sizeof(elems)/sizeof(*elems), script, scriptLen);
    
    if (count == 5 && *elems[0] == OP_DUP && *elems[1] == OP_HASH160 && *elems[2] == 20 &&
        *elems[3] == OP_EQUALVERIFY && *elems[4] == OP_CHECKSIG) {
        // pay-to-pubkey-hash scriptPubKey
        data[0] = LITECOIN_PUBKEY_ADDRESS;
#if LITECOIN_TESTNET
        data[0] = LITECOIN_PUBKEY_ADDRESS_TEST;
#endif
        memcpy(&data[1], LWScriptData(elems[2], &l), 20);
        r = LWBase58CheckEncode(addr, addrLen, data, 21);
    }
    else if (count == 3 && *elems[0] == OP_HASH160 && *elems[1] == 20 && *elems[2] == OP_EQUAL) {
        // pay-to-script-hash scriptPubKey
        data[0] = LITECOIN_SCRIPT_ADDRESS;
#if LITECOIN_TESTNET
        data[0] = LITECOIN_SCRIPT_ADDRESS_TEST;
#endif
        memcpy(&data[1], LWScriptData(elems[1], &l), 20);
        r = LWBase58CheckEncode(addr, addrLen, data, 21);
    }
    else if (count == 2 && (*elems[0] == 65 || *elems[0] == 33) && *elems[1] == OP_CHECKSIG) {
        // pay-to-pubkey scriptPubKey
        data[0] = LITECOIN_PUBKEY_ADDRESS;
#if LITECOIN_TESTNET
        data[0] = LITECOIN_PUBKEY_ADDRESS_TEST;
#endif
        d = LWScriptData(elems[0], &l);
        LWHash160(&data[1], d, l);
        r = LWBase58CheckEncode(addr, addrLen, data, 21);
    }
    else if (count == 2 && ((*elems[0] == OP_0 && (*elems[1] == 20 || *elems[1] == 32)) ||
                            (*elems[0] >= OP_1 && *elems[0] <= OP_16 && *elems[1] >= 2 && *elems[1] <= 40))) {
        // pay-to-witness scriptPubKey
        r = LWBech32Encode(a, "ltc", script);
#if LITECOIN_TESTNET
        r = LWBech32Encode(a, "tltc", script);
#endif
        if (addr && r > addrLen) r = 0;
        if (addr) memcpy(addr, a, r);
    }
    
    return r;
}

// writes the bitcoin address for a scriptSig to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWAddressFromScriptSig(char *addr, size_t addrLen, const uint8_t *script, size_t scriptLen)
{
    assert(script != NULL || scriptLen == 0);
    if (! script || scriptLen == 0 || scriptLen > MAX_SCRIPT_LENGTH) return 0;
    
    uint8_t data[21];
    const uint8_t *elems[LWScriptElements(NULL, 0, script, scriptLen)], *d = NULL;
    size_t count = LWScriptElements(elems, sizeof(elems)/sizeof(*elems), script, scriptLen), l = 0;

    data[0] = LITECOIN_PUBKEY_ADDRESS;
#if LITECOIN_TESTNET
    data[0] = LITECOIN_PUBKEY_ADDRESS_TEST;
#endif
    
    if (count >= 2 && *elems[count - 2] <= OP_PUSHDATA4 &&
        (*elems[count - 1] == 65 || *elems[count - 1] == 33)) { // pay-to-pubkey-hash scriptSig
        d = LWScriptData(elems[count - 1], &l);
        if (l != 65 && l != 33) d = NULL;
        if (d) LWHash160(&data[1], d, l);
    }
    else if (count >= 2 && *elems[count - 2] <= OP_PUSHDATA4 && *elems[count - 1] <= OP_PUSHDATA4 &&
             *elems[count - 1] > 0) { // pay-to-script-hash scriptSig
        data[0] = LITECOIN_SCRIPT_ADDRESS;
#if LITECOIN_TESTNET
        data[0] = LITECOIN_SCRIPT_ADDRESS_TEST;
#endif
        d = LWScriptData(elems[count - 1], &l);
        if (d) LWHash160(&data[1], d, l);
    }
    else if (count >= 1 && *elems[count - 1] <= OP_PUSHDATA4 && *elems[count - 1] > 0) { // pay-to-pubkey scriptSig
        // TODO: implement Peter Wullie's pubKey recovery from signature
    }
    // pay-to-witness scriptSig's are empty
    
    return (d) ? LWBase58CheckEncode(addr, addrLen, data, 21) : 0;
}

// writes the bitcoin address for a witness to addr
// returns the number of bytes written, or addrLen needed if addr is NULL
size_t LWAddressFromWitness(char *addr, size_t addrLen, const uint8_t *witness, size_t witLen)
{
    return 0; // TODO: XXX implement
}

// writes the scriptPubKey for addr to script
// returns the number of bytes written, or scriptLen needed if script is NULL
size_t LWAddressScriptPubKey(uint8_t *script, size_t scriptLen, const char *addr)
{
    uint8_t data[42], pubkeyAddress = LITECOIN_PUBKEY_ADDRESS, scriptAddress = LITECOIN_SCRIPT_ADDRESS;
    char hrp[84], *bech32Prefix = "ltc";
    size_t dataLen, r = 0;
    
    assert(addr != NULL);

#if LITECOIN_TESTNET
    pubkeyAddress = LITECOIN_PUBKEY_ADDRESS_TEST;
    scriptAddress = LITECOIN_SCRIPT_ADDRESS_TEST;
    bech32Prefix = "tltc";
#endif
    
    if (LWBase58CheckDecode(data, sizeof(data), addr) == 21) {
        if (data[0] == pubkeyAddress) {
            if (script && 25 <= scriptLen) {
                script[0] = OP_DUP;
                script[1] = OP_HASH160;
                script[2] = 20;
                memcpy(&script[3], &data[1], 20);
                script[23] = OP_EQUALVERIFY;
                script[24] = OP_CHECKSIG;
            }
            
            r = (! script || 25 <= scriptLen) ? 25 : 0;
        }
        else if (data[0] == scriptAddress) {
            if (script && 23 <= scriptLen) {
                script[0] = OP_HASH160;
                script[1] = 20;
                memcpy(&script[2], &data[1], 20);
                script[22] = OP_EQUAL;
            }
            
            r = (! script || 23 <= scriptLen) ? 23 : 0;
        }
    }
    else {
        dataLen = LWBech32Decode(hrp, data, addr);
        
        if (dataLen > 2 && strcmp(hrp, bech32Prefix) == 0 && (data[0] != OP_0 || data[1] == 20 || data[1] == 32)) {
            if (script && dataLen <= scriptLen) memcpy(script, data, dataLen);
            r = (! script || dataLen <= scriptLen) ? dataLen : 0;
        }
    }

    return r;
}

// returns true if addr is a valid bitcoin address
int LWAddressIsValid(const char *addr)
{
    uint8_t data[42];
    char hrp[84];
    int r = 0;
    
    assert(addr != NULL);
    
    if (LWBase58CheckDecode(data, sizeof(data), addr) == 21) {
        r = (data[0] == LITECOIN_PUBKEY_ADDRESS || data[0] == LITECOIN_SCRIPT_ADDRESS);
    
#if LITECOIN_TESTNET
        r = (data[0] == LITECOIN_PUBKEY_ADDRESS_TEST || data[0] == LITECOIN_SCRIPT_ADDRESS_TEST);
#endif
    }
    else if (LWBech32Decode(hrp, data, addr) > 2) {
        r = (strcmp(hrp, "ltc") == 0 && (data[0] != OP_0 || data[1] == 20 || data[1] == 32));

#if LITECOIN_TESTNET
        r = (strcmp(hrp, "tltc") == 0 && (data[0] != OP_0 || data[1] == 20 || data[1] == 32));
#endif
    }
    
    return r;
}

// writes the 20 byte hash160 of addr to md20 and returns true on success
int LWAddressHash160(void *md20, const char *addr)
{
    uint8_t data[21];
    int r = 0;
    
    assert(md20 != NULL);
    assert(addr != NULL);
    r = (LWBase58CheckDecode(data, sizeof(data), addr) == 21);
    if (r) memcpy(md20, &data[1], 20);
    return r;
}
