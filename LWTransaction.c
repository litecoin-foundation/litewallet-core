//
//  LWTransaction.c
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#include "LWTransaction.h"
#include "LWKey.h"
#include "LWAddress.h"
#include "LWArray.h"
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#define TX_VERSION           0x00000001
#define TX_LOCKTIME          0x00000000
#define SIGHASH_ALL          0x01 // default, sign all of the outputs
#define SIGHASH_NONE         0x02 // sign none of the outputs, I don't care where the bitcoins go
#define SIGHASH_SINGLE       0x03 // sign one of the outputs, I don't care where the other outputs go
#define SIGHASH_ANYONECANPAY 0x80 // let other people add inputs, I don't care where the rest of the bitcoins come from
#define SIGHASH_FORKID       0x40 // use BIP143 digest method (for b-cash/b-gold signatures)

// returns a random number less than upperBound, for non-cryptographic use only
uint32_t LWRand(uint32_t upperBound)
{
    static int first = 1;
    uint32_t r;
    
    // seed = (((FNV_OFFSET xor time)*FNV_PRIME) xor pid)*FNV_PRIME
    if (first) srand((((0x811C9dc5 ^ (unsigned)time(NULL))*0x01000193) ^ (unsigned)getpid())*0x01000193);
    first = 0;
    if (upperBound == 0 || upperBound > LW_RAND_MAX) upperBound = LW_RAND_MAX;
    
    do { // to avoid modulo bias, find a rand value not less than 0x100000000 % upperBound
        r = rand();
    } while (r < ((0xffffffff - upperBound*2) + 1) % upperBound); // (((0xffffffff - x*2) + 1) % x) == (0x100000000 % x)

    return r % upperBound;
}

void LWTxInputSetAddress(LWTxInput *input, const char *address)
{
    assert(input != NULL);
    assert(address == NULL || LWAddressIsValid(address));
    if (input->script) array_free(input->script);
    input->script = NULL;
    input->scriptLen = 0;
    memset(input->address, 0, sizeof(input->address));

    if (address) {
        strncpy(input->address, address, sizeof(input->address) - 1);
        input->scriptLen = LWAddressScriptPubKey(NULL, 0, address);
        array_new(input->script, input->scriptLen);
        array_set_count(input->script, input->scriptLen);
        LWAddressScriptPubKey(input->script, input->scriptLen, address);
    }
}

void LWTxInputSetScript(LWTxInput *input, const uint8_t *script, size_t scriptLen)
{
    assert(input != NULL);
    assert(script != NULL || scriptLen == 0);
    if (input->script) array_free(input->script);
    input->script = NULL;
    input->scriptLen = 0;
    memset(input->address, 0, sizeof(input->address));
    
    if (script) {
        input->scriptLen = scriptLen;
        array_new(input->script, scriptLen);
        array_add_array(input->script, script, scriptLen);
        LWAddressFromScriptPubKey(input->address, sizeof(input->address), script, scriptLen);
    }
}

void LWTxInputSetSignature(LWTxInput *input, const uint8_t *signature, size_t sigLen)
{
    assert(input != NULL);
    assert(signature != NULL || sigLen == 0);
    if (input->signature) array_free(input->signature);
    input->signature = NULL;
    input->sigLen = 0;
    
    if (signature) {
        input->sigLen = sigLen;
        array_new(input->signature, sigLen);
        array_add_array(input->signature, signature, sigLen);
        if (! input->address[0]) LWAddressFromScriptSig(input->address, sizeof(input->address), signature, sigLen);
    }
}

static size_t _LWTxInputData(const LWTxInput *input, uint8_t *data, size_t dataLen)
{
    size_t off = 0;
    
    if (data && off + sizeof(UInt256) <= dataLen) memcpy(&data[off], &input->txHash, sizeof(UInt256)); // previous out
    off += sizeof(UInt256);
    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], input->index);
    off += sizeof(uint32_t);
    off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), input->sigLen);
    if (data && off + input->sigLen <= dataLen) memcpy(&data[off], input->signature, input->sigLen); // scriptSig
    off += input->sigLen;

    if (input->amount != 0) {
        if (data && off + sizeof(uint64_t) <= dataLen) UInt64SetLE(&data[off], input->amount);
        off += sizeof(uint64_t);
    }

    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], input->sequence);
    off += sizeof(uint32_t);
    return (! data || off <= dataLen) ? off : 0;
}

void LWTxOutputSetAddress(LWTxOutput *output, const char *address)
{
    assert(output != NULL);
    assert(address == NULL || LWAddressIsValid(address));
    if (output->script) array_free(output->script);
    output->script = NULL;
    output->scriptLen = 0;
    memset(output->address, 0, sizeof(output->address));

    if (address) {
        strncpy(output->address, address, sizeof(output->address) - 1);
        output->scriptLen = LWAddressScriptPubKey(NULL, 0, address);
        array_new(output->script, output->scriptLen);
        array_set_count(output->script, output->scriptLen);
        LWAddressScriptPubKey(output->script, output->scriptLen, address);
    }
}

void LWTxOutputSetScript(LWTxOutput *output, const uint8_t *script, size_t scriptLen)
{
    assert(output != NULL);
    if (output->script) array_free(output->script);
    output->script = NULL;
    output->scriptLen = 0;
    memset(output->address, 0, sizeof(output->address));

    if (script) {
        output->scriptLen = scriptLen;
        array_new(output->script, scriptLen);
        array_add_array(output->script, script, scriptLen);
        LWAddressFromScriptPubKey(output->address, sizeof(output->address), script, scriptLen);
    }
}

static size_t _LWTransactionOutputData(const LWTransaction *tx, uint8_t *data, size_t dataLen, size_t index)
{
    LWTxOutput *output;
    size_t i, off = 0;
    
    for (i = (index == SIZE_MAX ? 0 : index); i < tx->outCount && (index == SIZE_MAX || index == i); i++) {
        output = &tx->outputs[i];
        if (data && off + sizeof(uint64_t) <= dataLen) UInt64SetLE(&data[off], output->amount);
        off += sizeof(uint64_t);
        off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), output->scriptLen);
        if (data && off + output->scriptLen <= dataLen) memcpy(&data[off], output->script, output->scriptLen);
        off += output->scriptLen;
    }
    
    return (! data || off <= dataLen) ? off : 0;
}

// writes the BIP143 witness program data that needs to be hashed and signed for the tx input at index
// https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
// an index of SIZE_MAX will write the entire signed transaction
// returns number of bytes written, or total len needed if data is NULL
static size_t _LWTransactionWitnessData(const LWTransaction *tx, uint8_t *data, size_t dataLen, size_t index,
                                        int hashType)
{
    LWTxInput input;
    int anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY), sigHash = (hashType & 0x1f);
    size_t i, off = 0;
    
    if (index >= tx->inCount) return 0;
    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], tx->version); // tx version
    off += sizeof(uint32_t);
    
    if (! anyoneCanPay) {
        uint8_t buf[(sizeof(UInt256) + sizeof(uint32_t))*tx->inCount];
        
        for (i = 0; i < tx->inCount; i++) {
            UInt256Set(&buf[(sizeof(UInt256) + sizeof(uint32_t))*i], tx->inputs[i].txHash);
            UInt32SetLE(&buf[(sizeof(UInt256) + sizeof(uint32_t))*i + sizeof(UInt256)], tx->inputs[i].index);
        }
        
        if (data && off + sizeof(UInt256) <= dataLen) LWSHA256_2(&data[off], buf, sizeof(buf)); // inputs hash
    }
    else if (data && off + sizeof(UInt256) <= dataLen) UInt256Set(&data[off], UINT256_ZERO); // anyone-can-pay
    
    off += sizeof(UInt256);
    
    if (! anyoneCanPay && sigHash != SIGHASH_SINGLE && sigHash != SIGHASH_NONE) {
        uint8_t buf[sizeof(uint32_t)*tx->inCount];
        
        for (i = 0; i < tx->inCount; i++) UInt32SetLE(&buf[sizeof(uint32_t)*i], tx->inputs[i].sequence);
        if (data && off + sizeof(UInt256) <= dataLen) LWSHA256_2(&data[off], buf, sizeof(buf)); // sequence hash
    }
    else if (data && off + sizeof(UInt256) <= dataLen) UInt256Set(&data[off], UINT256_ZERO);
    
    off += sizeof(UInt256);
    input = tx->inputs[index];
    input.signature = input.script; // TODO: handle OP_CODESEPARATOR
    input.sigLen = input.scriptLen;
    off += _LWTxInputData(&input, (data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0));
    
    if (sigHash != SIGHASH_SINGLE && sigHash != SIGHASH_NONE) {
        size_t bufLen = _LWTransactionOutputData(tx, NULL, 0, SIZE_MAX);
        uint8_t _buf[(bufLen <= 0x1000) ? bufLen : 0], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);
        
        bufLen = _LWTransactionOutputData(tx, buf, bufLen, SIZE_MAX);
        if (data && off + sizeof(UInt256) <= dataLen) LWSHA256_2(&data[off], buf, bufLen); // SIGHASH_ALL outputs hash
        if (buf != _buf) free(buf);
    }
    else if (sigHash == SIGHASH_SINGLE && index < tx->outCount) {
        uint8_t buf[_LWTransactionOutputData(tx, NULL, 0, index)];
        size_t bufLen = _LWTransactionOutputData(tx, buf, sizeof(buf), index);
        
        if (data && off + sizeof(UInt256) <= dataLen) LWSHA256_2(&data[off], buf, bufLen); //SIGHASH_SINGLE outputs hash
    }
    else if (data && off + sizeof(UInt256) <= dataLen) UInt256Set(&data[off], UINT256_ZERO); // SIGHASH_NONE
    
    off += sizeof(UInt256);
    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], tx->lockTime); // locktime
    off += sizeof(uint32_t);
    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], hashType); // hash type
    off += sizeof(uint32_t);
    return (! data || off <= dataLen) ? off : 0;
}

// writes the data that needs to be hashed and signed for the tx input at index
// an index of SIZE_MAX will write the entire signed transaction
// returns number of bytes written, or total dataLen needed if data is NULL
static size_t _LWTransactionData(const LWTransaction *tx, uint8_t *data, size_t dataLen, size_t index, int hashType)
{
    LWTxInput input;
    int anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY), sigHash = (hashType & 0x1f);
    size_t i, off = 0;
    
    if (hashType & SIGHASH_FORKID) return _LWTransactionWitnessData(tx, data, dataLen, index, hashType);
    if (anyoneCanPay && index >= tx->inCount) return 0;
    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], tx->version); // tx version
    off += sizeof(uint32_t);
    
    if (! anyoneCanPay) {
        off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), tx->inCount);
        
        for (i = 0; i < tx->inCount; i++) { // inputs
            input = tx->inputs[i];
            
            if (index == i || (index == SIZE_MAX && ! input.signature)) {
                input.signature = input.script; // TODO: handle OP_CODESEPARATOR
                input.sigLen = input.scriptLen;
                if (index == i) input.amount = 0;
            }
            else if (index != SIZE_MAX) {
                input.sigLen = 0;
                if (sigHash == SIGHASH_NONE || sigHash == SIGHASH_SINGLE) input.sequence = 0;
                input.amount = 0;
            }
            else input.amount = 0;
            
            off += _LWTxInputData(&input, (data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0));
        }
    }
    else {
        off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), 1);
        input = tx->inputs[index];
        input.signature = input.script; // TODO: handle OP_CODESEPARATOR
        input.sigLen = input.scriptLen;
        input.amount = 0;
        off += _LWTxInputData(&input, (data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0));
    }
    
    if (sigHash != SIGHASH_SINGLE && sigHash != SIGHASH_NONE) { // SIGHASH_ALL outputs
        off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), tx->outCount);
        off += _LWTransactionOutputData(tx, (data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), SIZE_MAX);
    }
    else if (sigHash == SIGHASH_SINGLE && index < tx->outCount) { // SIGHASH_SINGLE outputs
        off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), index + 1);
        
        for (i = 0; i < index; i++)  {
            if (data && off + sizeof(uint64_t) <= dataLen) UInt64SetLE(&data[off], -1LL);
            off += sizeof(uint64_t);
            off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), 0);
        }
        
        off += _LWTransactionOutputData(tx, (data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), index);
    }
    else off += LWVarIntSet((data ? &data[off] : NULL), (off <= dataLen ? dataLen - off : 0), 0); //SIGHASH_NONE outputs
    
    if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], tx->lockTime); // locktime
    off += sizeof(uint32_t);
    
    if (index != SIZE_MAX) {
        if (data && off + sizeof(uint32_t) <= dataLen) UInt32SetLE(&data[off], hashType); // hash type
        off += sizeof(uint32_t);
    }
    
    return (! data || off <= dataLen) ? off : 0;
}

// returns a newly allocated empty transaction that must be freed by calling LWTransactionFree()
LWTransaction *LWTransactionNew(void)
{
    LWTransaction *tx = calloc(1, sizeof(*tx));

    assert(tx != NULL);
    tx->version = TX_VERSION;
    array_new(tx->inputs, 1);
    array_new(tx->outputs, 2);
    tx->lockTime = TX_LOCKTIME;
    tx->blockHeight = TX_UNCONFIRMED;
    return tx;
}

// returns a deep copy of tx and that must be freed by calling LWTransactionFree()
LWTransaction *LWTransactionCopy(const LWTransaction *tx)
{
    LWTransaction *cpy = LWTransactionNew();
    LWTxInput *inputs = cpy->inputs;
    LWTxOutput *outputs = cpy->outputs;
    
    assert(tx != NULL);
    *cpy = *tx;
    cpy->inputs = inputs;
    cpy->outputs = outputs;
    cpy->inCount = cpy->outCount = 0;

    for (size_t i = 0; i < tx->inCount; i++) {
        LWTransactionAddInput(cpy, tx->inputs[i].txHash, tx->inputs[i].index, tx->inputs[i].amount,
                              tx->inputs[i].script, tx->inputs[i].scriptLen,
                              tx->inputs[i].signature, tx->inputs[i].sigLen, tx->inputs[i].sequence);
    }
    
    for (size_t i = 0; i < tx->outCount; i++) {
        LWTransactionAddOutput(cpy, tx->outputs[i].amount, tx->outputs[i].script, tx->outputs[i].scriptLen);
    }

    return cpy;
}

// buf must contain a serialized tx
// retruns a transaction that must be freed by calling LWTransactionFree()
LWTransaction *LWTransactionParse(const uint8_t *buf, size_t bufLen)
{
    assert(buf != NULL || bufLen == 0);
    if (! buf) return NULL;
    
    int isSigned = 1;
    size_t i, off = 0, sLen = 0, len = 0;
    LWTransaction *tx = LWTransactionNew();
    LWTxInput *input;
    LWTxOutput *output;
    
    tx->version = (off + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[off]) : 0;
    off += sizeof(uint32_t);
    tx->inCount = (size_t)LWVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
    off += len;
    array_set_count(tx->inputs, tx->inCount);
    
    for (i = 0; off <= bufLen && i < tx->inCount; i++) {
        input = &tx->inputs[i];
        input->txHash = (off + sizeof(UInt256) <= bufLen) ? UInt256Get(&buf[off]) : UINT256_ZERO;
        off += sizeof(UInt256);
        input->index = (off + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[off]) : 0;
        off += sizeof(uint32_t);
        sLen = (size_t)LWVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
        off += len;
        
        if (off + sLen <= bufLen && LWAddressFromScriptPubKey(NULL, 0, &buf[off], sLen) > 0) {
            LWTxInputSetScript(input, &buf[off], sLen);
            input->amount = (off + sLen + sizeof(uint64_t) <= bufLen) ? UInt64GetLE(&buf[off + sLen]) : 0;
            off += sizeof(uint64_t);
            isSigned = 0;
        }
        else if (off + sLen <= bufLen) LWTxInputSetSignature(input, &buf[off], sLen);
        
        off += sLen;
        input->sequence = (off + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[off]) : 0;
        off += sizeof(uint32_t);
    }
    
    tx->outCount = (size_t)LWVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
    off += len;
    array_set_count(tx->outputs, tx->outCount);
    
    for (i = 0; off <= bufLen && i < tx->outCount; i++) {
        output = &tx->outputs[i];
        output->amount = (off + sizeof(uint64_t) <= bufLen) ? UInt64GetLE(&buf[off]) : 0;
        off += sizeof(uint64_t);
        sLen = (size_t)LWVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
        off += len;
        if (off + sLen <= bufLen) LWTxOutputSetScript(output, &buf[off], sLen);
        off += sLen;
    }
    
    tx->lockTime = (off + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[off]) : 0;
    off += sizeof(uint32_t);
    
    if (tx->inCount == 0 || off > bufLen) {
        LWTransactionFree(tx);
        tx = NULL;
    }
    else if (isSigned) LWSHA256_2(&tx->txHash, buf, off);
    
    return tx;
}

// returns number of bytes written to buf, or total bufLen needed if buf is NULL
// (tx->blockHeight and tx->timestamp are not serialized)
size_t LWTransactionSerialize(const LWTransaction *tx, uint8_t *buf, size_t bufLen)
{
    assert(tx != NULL);
    return (tx) ? _LWTransactionData(tx, buf, bufLen, SIZE_MAX, SIGHASH_ALL) : 0;
}

// adds an input to tx
void LWTransactionAddInput(LWTransaction *tx, UInt256 txHash, uint32_t index, uint64_t amount,
                           const uint8_t *script, size_t scriptLen, const uint8_t *signature, size_t sigLen,
                           uint32_t sequence)
{
    LWTxInput input = { txHash, index, "", amount, NULL, 0, NULL, 0, sequence };

    assert(tx != NULL);
    assert(! UInt256IsZero(txHash));
    assert(script != NULL || scriptLen == 0);
    assert(signature != NULL || sigLen == 0);
    
    if (tx) {
        if (script) LWTxInputSetScript(&input, script, scriptLen);
        if (signature) LWTxInputSetSignature(&input, signature, sigLen);
        array_add(tx->inputs, input);
        tx->inCount = array_count(tx->inputs);
    }
}

// adds an output to tx
void LWTransactionAddOutput(LWTransaction *tx, uint64_t amount, const uint8_t *script, size_t scriptLen)
{
    LWTxOutput output = { "", amount, NULL, 0 };
    
    assert(tx != NULL);
    assert(script != NULL || scriptLen == 0);
    
    if (tx) {
        LWTxOutputSetScript(&output, script, scriptLen);
        array_add(tx->outputs, output);
        tx->outCount = array_count(tx->outputs);
    }
}

// shuffles order of tx outputs
void LWTransactionShuffleOutputs(LWTransaction *tx)
{
    assert(tx != NULL);
    
    for (uint32_t i = 0; tx && i + 1 < tx->outCount; i++) { // fischer-yates shuffle
        uint32_t j = i + LWRand((uint32_t)tx->outCount - i);
        LWTxOutput t;
        
        if (j != i) {
            t = tx->outputs[i];
            tx->outputs[i] = tx->outputs[j];
            tx->outputs[j] = t;
        }
    }
}

// size in bytes if signed, or estimated size assuming compact pubkey sigs
size_t LWTransactionSize(const LWTransaction *tx)
{
    LWTxInput *input;
    size_t size;

    assert(tx != NULL);
    size = (tx) ? 8 + LWVarIntSize(tx->inCount) + LWVarIntSize(tx->outCount) : 0;
    
    for (size_t i = 0; tx && i < tx->inCount; i++) {
        input = &tx->inputs[i];
        
        if (input->signature) {
            size += sizeof(UInt256) + sizeof(uint32_t) + LWVarIntSize(input->sigLen) + input->sigLen + sizeof(uint32_t);
        }
        else size += TX_INPUT_SIZE;
    }
    
    for (size_t i = 0; tx && i < tx->outCount; i++) {
        size += sizeof(uint64_t) + LWVarIntSize(tx->outputs[i].scriptLen) + tx->outputs[i].scriptLen;
    }
    
    return size;
}

// minimum transaction fee needed for tx to relay across the bitcoin network
uint64_t LWTransactionStandardFee(const LWTransaction *tx)
{
    assert(tx != NULL);
    return ((LWTransactionSize(tx) + 999)/1000)*TX_FEE_PER_KB;
}

// checks if all signatures exist, but does not verify them
int LWTransactionIsSigned(const LWTransaction *tx)
{
    assert(tx != NULL);
    
    for (size_t i = 0; tx && i < tx->inCount; i++) {
        if (! tx->inputs[i].signature) return 0;
    }

    return (tx) ? 1 : 0;
}

// adds signatures to any inputs with NULL signatures that can be signed with any keys
// forkId is 0 for bitcoin, 0x40 for b-cash, 0x4f for b-gold
// returns true if tx is signed
int LWTransactionSign(LWTransaction *tx, int forkId, LWKey keys[], size_t keysCount)
{
    LWAddress addrs[keysCount], address;
    size_t i, j;
    
    assert(tx != NULL);
    assert(keys != NULL || keysCount == 0);
    
    for (i = 0; tx && i < keysCount; i++) {
        if (! LWKeyAddress(&keys[i], addrs[i].s, sizeof(addrs[i]))) addrs[i] = LW_ADDRESS_NONE;
    }
    
    for (i = 0; tx && i < tx->inCount; i++) {
        LWTxInput *input = &tx->inputs[i];
        
        if (! LWAddressFromScriptPubKey(address.s, sizeof(address), input->script, input->scriptLen)) continue;
        j = 0;
        while (j < keysCount && ! LWAddressEq(&addrs[j], &address)) j++;
        if (j >= keysCount) continue;
        
        const uint8_t *elems[LWScriptElements(NULL, 0, input->script, input->scriptLen)];
        size_t elemsCount = LWScriptElements(elems, sizeof(elems)/sizeof(*elems), input->script, input->scriptLen);
        uint8_t pubKey[LWKeyPubKey(&keys[j], NULL, 0)];
        size_t pkLen = LWKeyPubKey(&keys[j], pubKey, sizeof(pubKey));
        uint8_t sig[73], script[1 + sizeof(sig) + 1 + sizeof(pubKey)];
        size_t sigLen, scriptLen;
        UInt256 md = UINT256_ZERO;
        
        if (elemsCount >= 2 && *elems[elemsCount - 2] == OP_EQUALVERIFY) { // pay-to-pubkey-hash
            uint8_t data[_LWTransactionData(tx, NULL, 0, i, forkId | SIGHASH_ALL)];
            size_t dataLen = _LWTransactionData(tx, data, sizeof(data), i, forkId | SIGHASH_ALL);
            
            LWSHA256_2(&md, data, dataLen);
            sigLen = LWKeySign(&keys[j], sig, sizeof(sig) - 1, md);
            sig[sigLen++] = forkId | SIGHASH_ALL;
            scriptLen = LWScriptPushData(script, sizeof(script), sig, sigLen);
            scriptLen += LWScriptPushData(&script[scriptLen], sizeof(script) - scriptLen, pubKey, pkLen);
            LWTxInputSetSignature(input, script, scriptLen);
        }
        else { // pay-to-pubkey
            uint8_t data[_LWTransactionData(tx, NULL, 0, i, forkId | SIGHASH_ALL)];
            size_t dataLen = _LWTransactionData(tx, data, sizeof(data), i, forkId | SIGHASH_ALL);
            
            LWSHA256_2(&md, data, dataLen);
            sigLen = LWKeySign(&keys[j], sig, sizeof(sig) - 1, md);
            sig[sigLen++] = forkId | SIGHASH_ALL;
            scriptLen = LWScriptPushData(script, sizeof(script), sig, sigLen);
            LWTxInputSetSignature(input, script, scriptLen);
        }
    }
    
    if (tx && LWTransactionIsSigned(tx)) {
        uint8_t data[_LWTransactionData(tx, NULL, 0, SIZE_MAX, 0)];
        size_t len = _LWTransactionData(tx, data, sizeof(data), SIZE_MAX, 0);
        
        LWSHA256_2(&tx->txHash, data, len);
        return 1;
    }
    else return 0;
}

// true if tx meets IsStandard() rules: https://bitcoin.org/en/developer-guide#standard-transactions
int LWTransactionIsStandard(const LWTransaction *tx)
{
    int r = 1;
    
    // TODO: XXX implement
    
    return r;
}

// frees memory allocated for tx
void LWTransactionFree(LWTransaction *tx)
{
    assert(tx != NULL);
    
    if (tx) {
        for (size_t i = 0; i < tx->inCount; i++) {
            LWTxInputSetScript(&tx->inputs[i], NULL, 0);
            LWTxInputSetSignature(&tx->inputs[i], NULL, 0);
        }

        for (size_t i = 0; i < tx->outCount; i++) {
            LWTxOutputSetScript(&tx->outputs[i], NULL, 0);
        }

        array_free(tx->outputs);
        array_free(tx->inputs);
        free(tx);
    }
}
