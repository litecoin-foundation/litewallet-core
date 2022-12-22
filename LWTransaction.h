//
//  LWTransaction.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWTransaction_h
#define LWTransaction_h

#include "LWKey.h"
#include "LWInt.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TX_FEE_PER_KB        1000ULL     // standard tx fee per kb of tx size, rounded up to nearest kb
#define TX_OUTPUT_SIZE       34          // estimated size for a typical transaction output
#define TX_INPUT_SIZE        148         // estimated size for a typical compact pubkey transaction input
#define TX_MIN_OUTPUT_AMOUNT (TX_FEE_PER_KB*3*(TX_OUTPUT_SIZE + TX_INPUT_SIZE)/1000) //no txout can be below this amount
#define TX_MAX_SIZE          100000      // no tx can be larger than this size in bytes
#define TX_FREE_MAX_SIZE     1000        // tx must not be larger than this size in bytes without a fee
#define TX_FREE_MIN_PRIORITY 57600000ULL // tx must not have a priority below this value without a fee
#define TX_UNCONFIRMED       INT32_MAX   // block height indicating transaction is unconfirmed
#define TX_MAX_LOCK_HEIGHT   500000000   // a lockTime below this value is a block height, otherwise a timestamp

#define TXIN_SEQUENCE        UINT32_MAX  // sequence number for a finalized tx input

#define SATOSHIS             100000000LL
#define MAX_MONEY            (84000000LL*SATOSHIS)

#define LW_RAND_MAX          ((RAND_MAX > 0x7fffffff) ? 0x7fffffff : RAND_MAX)

// returns a random number less than upperBound (for non-cryptographic use only)
uint32_t LWRand(uint32_t upperBound);

typedef struct {
    UInt256 txHash;
    uint32_t index;
    char address[75];
    uint64_t amount;
    uint8_t *script;
    size_t scriptLen;
    uint8_t *signature;
    size_t sigLen;
    uint32_t sequence;
} LWTxInput;

void LWTxInputSetAddress(LWTxInput *input, const char *address);
void LWTxInputSetScript(LWTxInput *input, const uint8_t *script, size_t scriptLen);
void LWTxInputSetSignature(LWTxInput *input, const uint8_t *signature, size_t sigLen);

typedef struct {
    char address[75];
    uint64_t amount;
    uint8_t *script;
    size_t scriptLen;
} LWTxOutput;

#define LW_TX_OUTPUT_NONE ((LWTxOutput) { "", 0, NULL, 0 })

// when creating a LWTxOutput struct outside of a LWTransaction, set address or script to NULL when done to free memory
void LWTxOutputSetAddress(LWTxOutput *output, const char *address);
void LWTxOutputSetScript(LWTxOutput *output, const uint8_t *script, size_t scriptLen);

typedef struct {
    UInt256 txHash;
    uint32_t version;
    LWTxInput *inputs;
    size_t inCount;
    LWTxOutput *outputs;
    size_t outCount;
    uint32_t lockTime;
    uint32_t blockHeight;
    uint32_t timestamp; // time interval since unix epoch
} LWTransaction;

// returns a newly allocated empty transaction that must be freed by calling LWTransactionFree()
LWTransaction *LWTransactionNew(void);

// returns a deep copy of tx and that must be freed by calling LWTransactionFree()
LWTransaction *LWTransactionCopy(const LWTransaction *tx);

// buf must contain a serialized tx
// retruns a transaction that must be freed by calling LWTransactionFree()
LWTransaction *LWTransactionParse(const uint8_t *buf, size_t bufLen);

// returns number of bytes written to buf, or total bufLen needed if buf is NULL
// (tx->blockHeight and tx->timestamp are not serialized)
size_t LWTransactionSerialize(const LWTransaction *tx, uint8_t *buf, size_t bufLen);

// adds an input to tx
void LWTransactionAddInput(LWTransaction *tx, UInt256 txHash, uint32_t index, uint64_t amount,
                           const uint8_t *script, size_t scriptLen, const uint8_t *signature, size_t sigLen,
                           uint32_t sequence);

// adds an output to tx
void LWTransactionAddOutput(LWTransaction *tx, uint64_t amount, const uint8_t *script, size_t scriptLen);

// shuffles order of tx outputs
void LWTransactionShuffleOutputs(LWTransaction *tx);

// size in bytes if signed, or estimated size assuming compact pubkey sigs
size_t LWTransactionSize(const LWTransaction *tx);

// minimum transaction fee needed for tx to relay across the bitcoin network
uint64_t LWTransactionStandardFee(const LWTransaction *tx);

// checks if all signatures exist, but does not verify them
int LWTransactionIsSigned(const LWTransaction *tx);

// adds signatures to any inputs with NULL signatures that can be signed with any keys
// forkId is 0 for bitcoin, 0x40 for b-cash, 0x4f for b-gold
// returns true if tx is signed
int LWTransactionSign(LWTransaction *tx, int forkId, LWKey keys[], size_t keysCount);

// true if tx meets IsStandard() rules: https://bitcoin.org/en/developer-guide#standard-transactions
int LWTransactionIsStandard(const LWTransaction *tx);

// returns a hash value for tx suitable for use in a hashtable
inline static size_t LWTransactionHash(const void *tx)
{
    return (size_t)((const LWTransaction *)tx)->txHash.u32[0];
}

// true if tx and otherTx have equal txHash values
inline static int LWTransactionEq(const void *tx, const void *otherTx)
{
    return (tx == otherTx || UInt256Eq(((const LWTransaction *)tx)->txHash, ((const LWTransaction *)otherTx)->txHash));
}

// frees memory allocated for tx
void LWTransactionFree(LWTransaction *tx);

#ifdef __cplusplus
}
#endif

#endif // LWTransaction_h
