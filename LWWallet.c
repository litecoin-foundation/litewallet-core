//
//  LWWallet.c
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#include "LWWallet.h"
#include "LWSet.h"
#include "LWAddress.h"
#include "LWArray.h"
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <float.h>
#include <pthread.h>
#include <assert.h>

struct LWWalletStruct {
    uint64_t balance, totalSent, totalReceived, feePerKb, *balanceHist;
    uint32_t blockHeight;
    LWUTXO *utxos;
    LWTransaction **transactions;
    LWMasterPubKey masterPubKey;
    LWAddress *internalChain, *externalChain;
    LWSet *allTx, *invalidTx, *pendingTx, *spentOutputs, *usedAddrs, *allAddrs;
    void *callbackInfo;
    void (*balanceChanged)(void *info, uint64_t balance);
    void (*txAdded)(void *info, LWTransaction *tx);
    void (*txUpdated)(void *info, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight, uint32_t timestamp);
    void (*txDeleted)(void *info, UInt256 txHash, int notifyUser, int recommendRescan);
    pthread_mutex_t lock;
};

inline static uint64_t _txFee(uint64_t feePerKb, size_t size)
{
    uint64_t standardFee = ((size + 999)/1000)*TX_FEE_PER_KB, // standard fee based on tx size rounded up to nearest kb
             fee = (((size*feePerKb/1000) + 99)/100)*100; // fee using feePerKb, rounded up to nearest 100 satoshi
    
    return (fee > standardFee) ? fee : standardFee;
}

// chain position of first tx output address that appears in chain
inline static size_t _txChainIndex(const LWTransaction *tx, const LWAddress *addrChain)
{
    for (size_t i = array_count(addrChain); i > 0; i--) {
        for (size_t j = 0; j < tx->outCount; j++) {
            if (LWAddressEq(tx->outputs[j].address, &addrChain[i - 1])) return i - 1;
        }
    }
    
    return SIZE_MAX;
}

inline static int _LWWalletTxIsAscending(LWWallet *wallet, const LWTransaction *tx1, const LWTransaction *tx2)
{
    if (! tx1 || ! tx2) return 0;
    if (tx1->blockHeight > tx2->blockHeight) return 1;
    if (tx1->blockHeight < tx2->blockHeight) return 0;
    
    for (size_t i = 0; i < tx1->inCount; i++) {
        if (UInt256Eq(tx1->inputs[i].txHash, tx2->txHash)) return 1;
    }
    
    for (size_t i = 0; i < tx2->inCount; i++) {
        if (UInt256Eq(tx2->inputs[i].txHash, tx1->txHash)) return 0;
    }

    for (size_t i = 0; i < tx1->inCount; i++) {
        if (_LWWalletTxIsAscending(wallet, LWSetGet(wallet->allTx, &(tx1->inputs[i].txHash)), tx2)) return 1;
    }

    return 0;
}

inline static int _LWWalletTxCompare(LWWallet *wallet, const LWTransaction *tx1, const LWTransaction *tx2)
{
    size_t i, j;

    if (_LWWalletTxIsAscending(wallet, tx1, tx2)) return 1;
    if (_LWWalletTxIsAscending(wallet, tx2, tx1)) return -1;
    i = _txChainIndex(tx1, wallet->internalChain);
    j = _txChainIndex(tx2, (i == SIZE_MAX) ? wallet->externalChain : wallet->internalChain);
    if (i == SIZE_MAX && j != SIZE_MAX) i = _txChainIndex((LWTransaction *)tx1, wallet->externalChain);
    if (i != SIZE_MAX && j != SIZE_MAX && i != j) return (i > j) ? 1 : -1;
    return 0;
}

// inserts tx into wallet->transactions, keeping wallet->transactions sorted by date, oldest first (insertion sort)
inline static void _LWWalletInsertTx(LWWallet *wallet, LWTransaction *tx)
{
    size_t i = array_count(wallet->transactions);
    
    array_set_count(wallet->transactions, i + 1);
    
    while (i > 0 && _LWWalletTxCompare(wallet, wallet->transactions[i - 1], tx) > 0) {
        wallet->transactions[i] = wallet->transactions[i - 1];
        i--;
    }
    
    wallet->transactions[i] = tx;
}

// non-threadsafe version of LWWalletContainsTransaction()
static int _LWWalletContainsTx(LWWallet *wallet, const LWTransaction *tx)
{
    int r = 0;
    
    for (size_t i = 0; ! r && i < tx->outCount; i++) {
        if (LWSetContains(wallet->allAddrs, tx->outputs[i].address)) r = 1;
    }
    
    for (size_t i = 0; ! r && i < tx->inCount; i++) {
        LWTransaction *t = LWSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;
        
        if (t && n < t->outCount && LWSetContains(wallet->allAddrs, t->outputs[n].address)) r = 1;
    }
    
    return r;
}

//static int _LWWalletTxIsSend(LWWallet *wallet, LWTransaction *tx)
//{
//    int r = 0;
//    
//    for (size_t i = 0; ! r && i < tx->inCount; i++) {
//        if (LWSetContains(wallet->allAddrs, tx->inputs[i].address)) r = 1;
//    }
//    
//    return r;
//}

static void _LWWalletUpdateBalance(LWWallet *wallet)
{
    int isInvalid, isPending;
    uint64_t balance = 0, prevBalance = 0;
    time_t now = time(NULL);
    size_t i, j;
    LWTransaction *tx, *t;
    
    array_clear(wallet->utxos);
    array_clear(wallet->balanceHist);
    LWSetClear(wallet->spentOutputs);
    LWSetClear(wallet->invalidTx);
    LWSetClear(wallet->pendingTx);
    LWSetClear(wallet->usedAddrs);
    wallet->totalSent = 0;
    wallet->totalReceived = 0;

    for (i = 0; i < array_count(wallet->transactions); i++) {
        tx = wallet->transactions[i];

        // check if any inputs are invalid or already spent
        if (tx->blockHeight == TX_UNCONFIRMED) {
            for (j = 0, isInvalid = 0; ! isInvalid && j < tx->inCount; j++) {
                if (LWSetContains(wallet->spentOutputs, &tx->inputs[j]) ||
                    LWSetContains(wallet->invalidTx, &tx->inputs[j].txHash)) isInvalid = 1;
            }
        
            if (isInvalid) {
                LWSetAdd(wallet->invalidTx, tx);
                array_add(wallet->balanceHist, balance);
                continue;
            }
        }

        // add inputs to spent output set
        for (j = 0; j < tx->inCount; j++) {
            LWSetAdd(wallet->spentOutputs, &tx->inputs[j]);
        }

        // check if tx is pending
        if (tx->blockHeight == TX_UNCONFIRMED) {
            isPending = (LWTransactionSize(tx) > TX_MAX_SIZE) ? 1 : 0; // check tx size is under TX_MAX_SIZE
            
            for (j = 0; ! isPending && j < tx->outCount; j++) {
                if (tx->outputs[j].amount < TX_MIN_OUTPUT_AMOUNT) isPending = 1; // check that no outputs are dust
            }

            for (j = 0; ! isPending && j < tx->inCount; j++) {
                if (tx->inputs[j].sequence < UINT32_MAX - 1) isPending = 1; // check for replace-by-fee
                if (tx->inputs[j].sequence < UINT32_MAX && tx->lockTime < TX_MAX_LOCK_HEIGHT &&
                    tx->lockTime > wallet->blockHeight + 1) isPending = 1; // future lockTime
                if (tx->inputs[j].sequence < UINT32_MAX && tx->lockTime > now) isPending = 1; // future lockTime
                if (LWSetContains(wallet->pendingTx, &tx->inputs[j].txHash)) isPending = 1; // check for pending inputs
                // TODO: XXX handle BIP68 check lock time verify rules
            }
            
            if (isPending) {
                LWSetAdd(wallet->pendingTx, tx);
                array_add(wallet->balanceHist, balance);
                continue;
            }
        }

        // add outputs to UTXO set
        // TODO: don't add outputs below TX_MIN_OUTPUT_AMOUNT
        // TODO: don't add coin generation outputs < 100 blocks deep
        // NOTE: balance/UTXOs will then need to be recalculated when last block changes
        for (j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].address[0] != '\0') {
                LWSetAdd(wallet->usedAddrs, tx->outputs[j].address);
                
                if (LWSetContains(wallet->allAddrs, tx->outputs[j].address)) {
                    array_add(wallet->utxos, ((LWUTXO) { tx->txHash, (uint32_t)j }));
                    balance += tx->outputs[j].amount;
                }
            }
        }

        // transaction ordering is not guaranteed, so check the entire UTXO set against the entire spent output set
        for (j = array_count(wallet->utxos); j > 0; j--) {
            if (! LWSetContains(wallet->spentOutputs, &wallet->utxos[j - 1])) continue;
            t = LWSetGet(wallet->allTx, &wallet->utxos[j - 1].hash);
            balance -= t->outputs[wallet->utxos[j - 1].n].amount;
            array_rm(wallet->utxos, j - 1);
        }
        
        if (prevBalance < balance) wallet->totalReceived += balance - prevBalance;
        if (balance < prevBalance) wallet->totalSent += prevBalance - balance;
        array_add(wallet->balanceHist, balance);
        prevBalance = balance;
    }

    assert(array_count(wallet->balanceHist) == array_count(wallet->transactions));
    wallet->balance = balance;
}

// allocates and populates a LWWallet struct which must be freed by calling LWWalletFree()
LWWallet *LWWalletNew(LWTransaction *transactions[], size_t txCount, LWMasterPubKey mpk)
{
    LWWallet *wallet = NULL;
    LWTransaction *tx;

    assert(transactions != NULL || txCount == 0);
    wallet = calloc(1, sizeof(*wallet));
    assert(wallet != NULL);
    array_new(wallet->utxos, 100);
    array_new(wallet->transactions, txCount + 100);
    wallet->feePerKb = DEFAULT_FEE_PER_KB;
    wallet->masterPubKey = mpk;
    array_new(wallet->internalChain, 100);
    array_new(wallet->externalChain, 100);
    array_new(wallet->balanceHist, txCount + 100);
    wallet->allTx = LWSetNew(LWTransactionHash, LWTransactionEq, txCount + 100);
    wallet->invalidTx = LWSetNew(LWTransactionHash, LWTransactionEq, 10);
    wallet->pendingTx = LWSetNew(LWTransactionHash, LWTransactionEq, 10);
    wallet->spentOutputs = LWSetNew(LWUTXOHash, LWUTXOEq, txCount + 100);
    wallet->usedAddrs = LWSetNew(LWAddressHash, LWAddressEq, txCount + 100);
    wallet->allAddrs = LWSetNew(LWAddressHash, LWAddressEq, txCount + 100);
    pthread_mutex_init(&wallet->lock, NULL);

    for (size_t i = 0; transactions && i < txCount; i++) {
        tx = transactions[i];
        if (! LWTransactionIsSigned(tx) || LWSetContains(wallet->allTx, tx)) continue;
        LWSetAdd(wallet->allTx, tx);
        _LWWalletInsertTx(wallet, tx);

        for (size_t j = 0; j < tx->outCount; j++) {
            if (tx->outputs[j].address[0] != '\0') LWSetAdd(wallet->usedAddrs, tx->outputs[j].address);
        }
    }
    
    LWWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0);
    LWWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1);
    _LWWalletUpdateBalance(wallet);

    if (txCount > 0 && ! _LWWalletContainsTx(wallet, transactions[0])) { // verify transactions match master pubKey
        LWWalletFree(wallet);
        wallet = NULL;
    }
    
    return wallet;
}

// not thread-safe, set callbacks once after LWWalletNew(), before calling other LWWallet functions
// info is a void pointer that will be passed along with each callback call
// void balanceChanged(void *, uint64_t) - called when the wallet balance changes
// void txAdded(void *, LWTransaction *) - called when transaction is added to the wallet
// void txUpdated(void *, const UInt256[], size_t, uint32_t, uint32_t)
//   - called when the blockHeight or timestamp of previously added transactions are updated
// void txDeleted(void *, UInt256) - called when a previously added transaction is removed from the wallet
// NOTE: if a transaction is deleted, and LWWalletAmountSentByTx() is greater than 0, recommend the user do a rescan
void LWWalletSetCallbacks(LWWallet *wallet, void *info,
                          void (*balanceChanged)(void *info, uint64_t balance),
                          void (*txAdded)(void *info, LWTransaction *tx),
                          void (*txUpdated)(void *info, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight,
                                            uint32_t timestamp),
                          void (*txDeleted)(void *info, UInt256 txHash, int notifyUser, int recommendRescan))
{
    assert(wallet != NULL);
    wallet->callbackInfo = info;
    wallet->balanceChanged = balanceChanged;
    wallet->txAdded = txAdded;
    wallet->txUpdated = txUpdated;
    wallet->txDeleted = txDeleted;
}

// wallets are composed of chains of addresses
// each chain is traversed until a gap of a number of addresses is found that haven't been used in any transactions
// this function writes to addrs an array of <gapLimit> unused addresses following the last used address in the chain
// the internal chain is used for change addresses and the external chain for receive addresses
// addrs may be NULL to only generate addresses for LWWalletContainsAddress()
// returns the number addresses written to addrs
size_t LWWalletUnusedAddrs(LWWallet *wallet, LWAddress addrs[], uint32_t gapLimit, int internal)
{
    LWAddress *addrChain;
    size_t i, j = 0, count, startCount;
    uint32_t chain = (internal) ? SEQUENCE_INTERNAL_CHAIN : SEQUENCE_EXTERNAL_CHAIN;

    assert(wallet != NULL);
    assert(gapLimit > 0);
    pthread_mutex_lock(&wallet->lock);
    addrChain = (internal) ? wallet->internalChain : wallet->externalChain;
    i = count = startCount = array_count(addrChain);
    
    // keep only the trailing contiguous block of addresses with no transactions
    while (i > 0 && ! LWSetContains(wallet->usedAddrs, &addrChain[i - 1])) i--;
    
    while (i + gapLimit > count) { // generate new addresses up to gapLimit
        LWKey key;
        LWAddress address = LW_ADDRESS_NONE;
        uint8_t pubKey[LWBIP32PubKey(NULL, 0, wallet->masterPubKey, chain, count)];
        size_t len = LWBIP32PubKey(pubKey, sizeof(pubKey), wallet->masterPubKey, chain, (uint32_t)count);
        
        if (! LWKeySetPubKey(&key, pubKey, len)) break;
        if (! LWKeyAddress(&key, address.s, sizeof(address)) || LWAddressEq(&address, &LW_ADDRESS_NONE)) break;
        array_add(addrChain, address);
        count++;
        if (LWSetContains(wallet->usedAddrs, &address)) i = count;
    }

    if (addrs && i + gapLimit <= count) {
        for (j = 0; j < gapLimit; j++) {
            addrs[j] = addrChain[i + j];
        }
    }
    
    // was addrChain moved to a new memory location?
    if (addrChain == (internal ? wallet->internalChain : wallet->externalChain)) {
        for (i = startCount; i < count; i++) {
            LWSetAdd(wallet->allAddrs, &addrChain[i]);
        }
    }
    else {
        if (internal) wallet->internalChain = addrChain;
        if (! internal) wallet->externalChain = addrChain;
        LWSetClear(wallet->allAddrs); // clear and rebuild allAddrs

        for (i = array_count(wallet->internalChain); i > 0; i--) {
            LWSetAdd(wallet->allAddrs, &wallet->internalChain[i - 1]);
        }
        
        for (i = array_count(wallet->externalChain); i > 0; i--) {
            LWSetAdd(wallet->allAddrs, &wallet->externalChain[i - 1]);
        }
    }

    pthread_mutex_unlock(&wallet->lock);
    return j;
}

// current wallet balance, not including transactions known to be invalid
uint64_t LWWalletBalance(LWWallet *wallet)
{
    uint64_t balance;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    balance = wallet->balance;
    pthread_mutex_unlock(&wallet->lock);
    return balance;
}

// writes unspent outputs to utxos and returns the number of outputs written, or total number available if utxos is NULL
size_t LWWalletUTXOs(LWWallet *wallet, LWUTXO *utxos, size_t utxosCount)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (! utxos || array_count(wallet->utxos) < utxosCount) utxosCount = array_count(wallet->utxos);

    for (size_t i = 0; utxos && i < utxosCount; i++) {
        utxos[i] = wallet->utxos[i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return utxosCount;
}

// writes transactions registered in the wallet, sorted by date, oldest first, to the given transactions array
// returns the number of transactions written, or total number available if transactions is NULL
size_t LWWalletTransactions(LWWallet *wallet, LWTransaction *transactions[], size_t txCount)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (! transactions || array_count(wallet->transactions) < txCount) txCount = array_count(wallet->transactions);

    for (size_t i = 0; transactions && i < txCount; i++) {
        transactions[i] = wallet->transactions[i];
    }
    
    pthread_mutex_unlock(&wallet->lock);
    return txCount;
}

// writes transactions registered in the wallet, and that were unconfirmed before blockHeight, to the transactions array
// returns the number of transactions written, or total number available if transactions is NULL
size_t LWWalletTxUnconfirmedBefore(LWWallet *wallet, LWTransaction *transactions[], size_t txCount,
                                   uint32_t blockHeight)
{
    size_t total, n = 0;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    total = array_count(wallet->transactions);
    while (n < total && wallet->transactions[(total - n) - 1]->blockHeight >= blockHeight) n++;
    if (! transactions || n < txCount) txCount = n;

    for (size_t i = 0; transactions && i < txCount; i++) {
        transactions[i] = wallet->transactions[(total - n) + i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return txCount;
}

// total amount spent from the wallet (exluding change)
uint64_t LWWalletTotalSent(LWWallet *wallet)
{
    uint64_t totalSent;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    totalSent = wallet->totalSent;
    pthread_mutex_unlock(&wallet->lock);
    return totalSent;
}

// total amount received by the wallet (exluding change)
uint64_t LWWalletTotalReceived(LWWallet *wallet)
{
    uint64_t totalReceived;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    totalReceived = wallet->totalReceived;
    pthread_mutex_unlock(&wallet->lock);
    return totalReceived;
}

// fee-per-kb of transaction size to use when creating a transaction
uint64_t LWWalletFeePerKb(LWWallet *wallet)
{
    uint64_t feePerKb;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    feePerKb = wallet->feePerKb;
    pthread_mutex_unlock(&wallet->lock);
    return feePerKb;
}

void LWWalletSetFeePerKb(LWWallet *wallet, uint64_t feePerKb)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    wallet->feePerKb = feePerKb;
    pthread_mutex_unlock(&wallet->lock);
}

// returns the first unused external address
LWAddress LWWalletReceiveAddress(LWWallet *wallet)
{
    LWAddress addr = LW_ADDRESS_NONE;
    
    LWWalletUnusedAddrs(wallet, &addr, 1, 0);
    return addr;
}

// writes all addresses previously genereated with LWWalletUnusedAddrs() to addrs
// returns the number addresses written, or total number available if addrs is NULL
size_t LWWalletAllAddrs(LWWallet *wallet, LWAddress addrs[], size_t addrsCount)
{
    size_t i, internalCount = 0, externalCount = 0;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    internalCount = (! addrs || array_count(wallet->internalChain) < addrsCount) ?
                    array_count(wallet->internalChain) : addrsCount;

    for (i = 0; addrs && i < internalCount; i++) {
        addrs[i] = wallet->internalChain[i];
    }

    externalCount = (! addrs || array_count(wallet->externalChain) < addrsCount - internalCount) ?
                    array_count(wallet->externalChain) : addrsCount - internalCount;

    for (i = 0; addrs && i < externalCount; i++) {
        addrs[internalCount + i] = wallet->externalChain[i];
    }

    pthread_mutex_unlock(&wallet->lock);
    return internalCount + externalCount;
}

// true if the address was previously generated by LWWalletUnusedAddrs() (even if it's now used)
int LWWalletContainsAddress(LWWallet *wallet, const char *addr)
{
    int r = 0;

    assert(wallet != NULL);
    assert(addr != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (addr) r = LWSetContains(wallet->allAddrs, addr);
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// true if the address was previously used as an output in any wallet transaction
int LWWalletAddressIsUsed(LWWallet *wallet, const char *addr)
{
    int r = 0;

    assert(wallet != NULL);
    assert(addr != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (addr) r = LWSetContains(wallet->usedAddrs, addr);
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// returns an unsigned transaction that sends the specified amount from the wallet to the given address
// result must be freed by calling LWTransactionFree()
LWTransaction *LWWalletCreateTransaction(LWWallet *wallet, uint64_t amount, const char *addr)
{
    LWTxOutput o = LW_TX_OUTPUT_NONE;
    
    assert(wallet != NULL);
    assert(amount > 0);
    assert(addr != NULL && LWAddressIsValid(addr));
    o.amount = amount;
    LWTxOutputSetAddress(&o, addr);
    return LWWalletCreateTxForOutputs(wallet, &o, 1);
}

// returns an unsigned transaction that satisifes the given transaction outputs
// result must be freed by calling LWTransactionFree()
LWTransaction *LWWalletCreateTxForOutputs(LWWallet *wallet, const LWTxOutput outputs[], size_t outCount)
{
    LWTransaction *tx, *transaction = LWTransactionNew();
    uint64_t feeAmount, amount = 0, balance = 0, minAmount;
    size_t i, j, cpfpSize = 0;
    LWUTXO *o;
    LWAddress addr = LW_ADDRESS_NONE;
    
    assert(wallet != NULL);
    assert(outputs != NULL && outCount > 0);

    for (i = 0; outputs && i < outCount; i++) {
        assert(outputs[i].script != NULL && outputs[i].scriptLen > 0);
        LWTransactionAddOutput(transaction, outputs[i].amount, outputs[i].script, outputs[i].scriptLen);
        amount += outputs[i].amount;
    }
    
    minAmount = LWWalletMinOutputAmount(wallet);
    pthread_mutex_lock(&wallet->lock);
    feeAmount = _txFee(wallet->feePerKb, LWTransactionSize(transaction) + TX_OUTPUT_SIZE);
    
    // TODO: use up all UTXOs for all used addresses to avoid leaving funds in addresses whose public key is revealed
    // TODO: avoid combining addresses in a single transaction when possible to reduce information leakage
    // TODO: use up UTXOs received from any of the output scripts that this transaction sends funds to, to mitigate an
    //       attacker double spending and requesting a refund
    for (i = 0; i < array_count(wallet->utxos); i++) {
        o = &wallet->utxos[i];
        tx = LWSetGet(wallet->allTx, o);
        if (! tx || o->n >= tx->outCount) continue;
        LWTransactionAddInput(transaction, tx->txHash, o->n, tx->outputs[o->n].amount,
                              tx->outputs[o->n].script, tx->outputs[o->n].scriptLen, NULL, 0, TXIN_SEQUENCE);
        
        if (LWTransactionSize(transaction) + TX_OUTPUT_SIZE > TX_MAX_SIZE) { // transaction size-in-bytes too large
            LWTransactionFree(transaction);
            transaction = NULL;
        
            // check for sufficient total funds before building a smaller transaction
            if (wallet->balance < amount + _txFee(wallet->feePerKb, 10 + array_count(wallet->utxos)*TX_INPUT_SIZE +
                                                  (outCount + 1)*TX_OUTPUT_SIZE + cpfpSize)) break;
            pthread_mutex_unlock(&wallet->lock);

            if (outputs[outCount - 1].amount > amount + feeAmount + minAmount - balance) {
                LWTxOutput newOutputs[outCount];
                
                for (j = 0; j < outCount; j++) {
                    newOutputs[j] = outputs[j];
                }
                
                newOutputs[outCount - 1].amount -= amount + feeAmount - balance; // reduce last output amount
                transaction = LWWalletCreateTxForOutputs(wallet, newOutputs, outCount);
            }
            else transaction = LWWalletCreateTxForOutputs(wallet, outputs, outCount - 1); // remove last output

            balance = amount = feeAmount = 0;
            pthread_mutex_lock(&wallet->lock);
            break;
        }
        
        balance += tx->outputs[o->n].amount;
        
//        // size of unconfirmed, non-change inputs for child-pays-for-parent fee
//        // don't include parent tx with more than 10 inputs or 10 outputs
//        if (tx->blockHeight == TX_UNCONFIRMED && tx->inCount <= 10 && tx->outCount <= 10 &&
//            ! _LWWalletTxIsSend(wallet, tx)) cpfpSize += LWTransactionSize(tx);

        // fee amount after adding a change output
        feeAmount = _txFee(wallet->feePerKb, LWTransactionSize(transaction) + TX_OUTPUT_SIZE + cpfpSize);

        // increase fee to round off remaining wallet balance to nearest 100 satoshi
        if (wallet->balance > amount + feeAmount) feeAmount += (wallet->balance - (amount + feeAmount)) % 100;
        
        if (balance == amount + feeAmount || balance >= amount + feeAmount + minAmount) break;
    }
    
    pthread_mutex_unlock(&wallet->lock);
    
    if (transaction && (outCount < 1 || balance < amount + feeAmount)) { // no outputs/insufficient funds
        LWTransactionFree(transaction);
        transaction = NULL;
    }
    else if (transaction && balance - (amount + feeAmount) > minAmount) { // add change output
        LWWalletUnusedAddrs(wallet, &addr, 1, 1);
        uint8_t script[LWAddressScriptPubKey(NULL, 0, addr.s)];
        size_t scriptLen = LWAddressScriptPubKey(script, sizeof(script), addr.s);
    
        LWTransactionAddOutput(transaction, balance - (amount + feeAmount), script, scriptLen);
        LWTransactionShuffleOutputs(transaction);
    }
    
    return transaction;
}

// signs any inputs in tx that can be signed using private keys from the wallet
// forkId is 0 for bitcoin, 0x40 for b-cash
// seed is the master private key (wallet seed) corresponding to the master public key given when the wallet was created
// returns true if all inputs were signed, or false if there was an error or not all inputs were able to be signed
int LWWalletSignTransaction(LWWallet *wallet, LWTransaction *tx, int forkId, const void *seed, size_t seedLen)
{
    uint32_t j, internalIdx[tx->inCount], externalIdx[tx->inCount];
    size_t i, internalCount = 0, externalCount = 0;
    int r = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    for (i = 0; tx && i < tx->inCount; i++) {
        for (j = (uint32_t)array_count(wallet->internalChain); j > 0; j--) {
            if (LWAddressEq(tx->inputs[i].address, &wallet->internalChain[j - 1])) internalIdx[internalCount++] = j - 1;
        }

        for (j = (uint32_t)array_count(wallet->externalChain); j > 0; j--) {
            if (LWAddressEq(tx->inputs[i].address, &wallet->externalChain[j - 1])) externalIdx[externalCount++] = j - 1;
        }
    }

    pthread_mutex_unlock(&wallet->lock);

    LWKey keys[internalCount + externalCount];

    if (seed) {
        LWBIP32PrivKeyList(keys, internalCount, seed, seedLen, SEQUENCE_INTERNAL_CHAIN, internalIdx);
        LWBIP32PrivKeyList(&keys[internalCount], externalCount, seed, seedLen, SEQUENCE_EXTERNAL_CHAIN, externalIdx);
        // TODO: XXX wipe seed callback
        seed = NULL;
        if (tx) r = LWTransactionSign(tx, forkId, keys, internalCount + externalCount);
        for (i = 0; i < internalCount + externalCount; i++) LWKeyClean(&keys[i]);
    }
    else r = -1; // user canceled authentication
    
    return r;
}

// true if the given transaction is associated with the wallet (even if it hasn't been registered)
int LWWalletContainsTransaction(LWWallet *wallet, const LWTransaction *tx)
{
    int r = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    if (tx) r = _LWWalletContainsTx(wallet, tx);
    pthread_mutex_unlock(&wallet->lock);
    return r;
}

// adds a transaction to the wallet, or returns false if it isn't associated with the wallet
int LWWalletRegisterTransaction(LWWallet *wallet, LWTransaction *tx)
{
    int wasAdded = 0, r = 1;
    
    assert(wallet != NULL);
    assert(tx != NULL && LWTransactionIsSigned(tx));
    
    if (tx && LWTransactionIsSigned(tx)) {
        pthread_mutex_lock(&wallet->lock);

        if (! LWSetContains(wallet->allTx, tx)) {
            if (_LWWalletContainsTx(wallet, tx)) {
                // TODO: verify signatures when possible
                // TODO: handle tx replacement with input sequence numbers
                //       (for now, replacements appear invalid until confirmation)
                LWSetAdd(wallet->allTx, tx);
                _LWWalletInsertTx(wallet, tx);
                _LWWalletUpdateBalance(wallet);
                wasAdded = 1;
            }
            else { // keep track of unconfirmed non-wallet tx for invalid tx checks and child-pays-for-parent fees
                   // BUG: limit total non-wallet unconfirmed tx to avoid memory exhaustion attack
                if (tx->blockHeight == TX_UNCONFIRMED) LWSetAdd(wallet->allTx, tx);
                r = 0;
                // BUG: XXX memory leak if tx is not added to wallet->allTx, and we can't just free it
            }
        }
    
        pthread_mutex_unlock(&wallet->lock);
    }
    else r = 0;

    if (wasAdded) {
        // when a wallet address is used in a transaction, generate a new address to replace it
        LWWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_EXTERNAL, 0);
        LWWalletUnusedAddrs(wallet, NULL, SEQUENCE_GAP_LIMIT_INTERNAL, 1);
        if (wallet->balanceChanged) wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
        if (wallet->txAdded) wallet->txAdded(wallet->callbackInfo, tx);
    }

    return r;
}

// removes a tx from the wallet and calls LWTransactionFree() on it, along with any tx that depend on its outputs
void LWWalletRemoveTransaction(LWWallet *wallet, UInt256 txHash)
{
    LWTransaction *tx, *t;
    UInt256 *hashes = NULL;
    int notifyUser = 0, recommendRescan = 0;

    assert(wallet != NULL);
    assert(! UInt256IsZero(txHash));
    pthread_mutex_lock(&wallet->lock);
    tx = LWSetGet(wallet->allTx, &txHash);

    if (tx) {
        array_new(hashes, 0);

        for (size_t i = array_count(wallet->transactions); i > 0; i--) { // find depedent transactions
            t = wallet->transactions[i - 1];
            if (t->blockHeight < tx->blockHeight) break;
            if (LWTransactionEq(tx, t)) continue;
            
            for (size_t j = 0; j < t->inCount; j++) {
                if (! UInt256Eq(t->inputs[j].txHash, txHash)) continue;
                array_add(hashes, t->txHash);
                break;
            }
        }
        
        if (array_count(hashes) > 0) {
            pthread_mutex_unlock(&wallet->lock);
            
            for (size_t i = array_count(hashes); i > 0; i--) {
                LWWalletRemoveTransaction(wallet, hashes[i - 1]);
            }
            
            LWWalletRemoveTransaction(wallet, txHash);
        }
        else {
            LWSetRemove(wallet->allTx, tx);
            
            for (size_t i = array_count(wallet->transactions); i > 0; i--) {
                if (! LWTransactionEq(wallet->transactions[i - 1], tx)) continue;
                array_rm(wallet->transactions, i - 1);
                break;
            }
            
            _LWWalletUpdateBalance(wallet);
            pthread_mutex_unlock(&wallet->lock);
            
            // if this is for a transaction we sent, and it wasn't already known to be invalid, notify user
            if (LWWalletAmountSentByTx(wallet, tx) > 0 && LWWalletTransactionIsValid(wallet, tx)) {
                recommendRescan = notifyUser = 1;
                
                for (size_t i = 0; i < tx->inCount; i++) { // only recommend a rescan if all inputs are confirmed
                    t = LWWalletTransactionForHash(wallet, tx->inputs[i].txHash);
                    if (t && t->blockHeight != TX_UNCONFIRMED) continue;
                    recommendRescan = 0;
                    break;
                }
            }

            if (wallet->balanceChanged) wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
            if (wallet->txDeleted) wallet->txDeleted(wallet->callbackInfo, txHash, notifyUser, recommendRescan);
            LWTransactionFree(tx);
        }
        
        array_free(hashes);
    }
    else pthread_mutex_unlock(&wallet->lock);
}

// returns the transaction with the given hash if it's been registered in the wallet
LWTransaction *LWWalletTransactionForHash(LWWallet *wallet, UInt256 txHash)
{
    LWTransaction *tx;
    
    assert(wallet != NULL);
    assert(! UInt256IsZero(txHash));
    pthread_mutex_lock(&wallet->lock);
    tx = LWSetGet(wallet->allTx, &txHash);
    pthread_mutex_unlock(&wallet->lock);
    return tx;
}

// true if no previous wallet transaction spends any of the given transaction's inputs, and no inputs are invalid
int LWWalletTransactionIsValid(LWWallet *wallet, const LWTransaction *tx)
{
    LWTransaction *t;
    int r = 1;

    assert(wallet != NULL);
    assert(tx != NULL && LWTransactionIsSigned(tx));
    
    // TODO: XXX attempted double spends should cause conflicted tx to remain unverified until they're confirmed
    // TODO: XXX conflicted tx with the same wallet outputs should be presented as the same tx to the user

    if (tx && tx->blockHeight == TX_UNCONFIRMED) { // only unconfirmed transactions can be invalid
        pthread_mutex_lock(&wallet->lock);

        if (! LWSetContains(wallet->allTx, tx)) {
            for (size_t i = 0; r && i < tx->inCount; i++) {
                if (LWSetContains(wallet->spentOutputs, &tx->inputs[i])) r = 0;
            }
        }
        else if (LWSetContains(wallet->invalidTx, tx)) r = 0;

        pthread_mutex_unlock(&wallet->lock);

        for (size_t i = 0; r && i < tx->inCount; i++) {
            t = LWWalletTransactionForHash(wallet, tx->inputs[i].txHash);
            if (t && ! LWWalletTransactionIsValid(wallet, t)) r = 0;
        }
    }
    
    return r;
}

// true if tx cannot be immediately spent (i.e. if it or an input tx can be replaced-by-fee)
int LWWalletTransactionIsPending(LWWallet *wallet, const LWTransaction *tx)
{
    LWTransaction *t;
    time_t now = time(NULL);
    uint32_t blockHeight;
    int r = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL && LWTransactionIsSigned(tx));
    pthread_mutex_lock(&wallet->lock);
    blockHeight = wallet->blockHeight;
    pthread_mutex_unlock(&wallet->lock);

    if (tx && tx->blockHeight == TX_UNCONFIRMED) { // only unconfirmed transactions can be postdated
        if (LWTransactionSize(tx) > TX_MAX_SIZE) r = 1; // check transaction size is under TX_MAX_SIZE
        
        for (size_t i = 0; ! r && i < tx->inCount; i++) {
            if (tx->inputs[i].sequence < UINT32_MAX - 1) r = 1; // check for replace-by-fee
            if (tx->inputs[i].sequence < UINT32_MAX && tx->lockTime < TX_MAX_LOCK_HEIGHT &&
                tx->lockTime > blockHeight + 1) r = 1; // future lockTime
            if (tx->inputs[i].sequence < UINT32_MAX && tx->lockTime > now) r = 1; // future lockTime
        }
        
        for (size_t i = 0; ! r && i < tx->outCount; i++) { // check that no outputs are dust
            if (tx->outputs[i].amount < TX_MIN_OUTPUT_AMOUNT) r = 1;
        }
        
        for (size_t i = 0; ! r && i < tx->inCount; i++) { // check if any inputs are known to be pending
            t = LWWalletTransactionForHash(wallet, tx->inputs[i].txHash);
            if (t && LWWalletTransactionIsPending(wallet, t)) r = 1;
        }
    }
    
    return r;
}

// true if tx is considered 0-conf safe (valid and not pending, timestamp is greater than 0, and no unverified inputs)
int LWWalletTransactionIsVerified(LWWallet *wallet, const LWTransaction *tx)
{
    LWTransaction *t;
    int r = 1;

    assert(wallet != NULL);
    assert(tx != NULL && LWTransactionIsSigned(tx));

    if (tx && tx->blockHeight == TX_UNCONFIRMED) { // only unconfirmed transactions can be unverified
        if (tx->timestamp == 0 || ! LWWalletTransactionIsValid(wallet, tx) ||
            LWWalletTransactionIsPending(wallet, tx)) r = 0;
            
        for (size_t i = 0; r && i < tx->inCount; i++) { // check if any inputs are known to be unverified
            t = LWWalletTransactionForHash(wallet, tx->inputs[i].txHash);
            if (t && ! LWWalletTransactionIsVerified(wallet, t)) r = 0;
        }
    }
    
    return r;
}

// set the block heights and timestamps for the given transactions
// use height TX_UNCONFIRMED and timestamp 0 to indicate a tx should remain marked as unverified (not 0-conf safe)
void LWWalletUpdateTransactions(LWWallet *wallet, const UInt256 txHashes[], size_t txCount, uint32_t blockHeight,
                                uint32_t timestamp)
{
    LWTransaction *tx;
    UInt256 hashes[txCount];
    int needsUpdate = 0;
    size_t i, j, k;
    
    assert(wallet != NULL);
    assert(txHashes != NULL || txCount == 0);
    pthread_mutex_lock(&wallet->lock);
    if (blockHeight > wallet->blockHeight) wallet->blockHeight = blockHeight;
    
    for (i = 0, j = 0; txHashes && i < txCount; i++) {
        tx = LWSetGet(wallet->allTx, &txHashes[i]);
        if (! tx || (tx->blockHeight == blockHeight && tx->timestamp == timestamp)) continue;
        tx->timestamp = timestamp;
        tx->blockHeight = blockHeight;
        
        if (_LWWalletContainsTx(wallet, tx)) {
            for (k = array_count(wallet->transactions); k > 0; k--) { // remove and re-insert tx to keep wallet sorted
                if (! LWTransactionEq(wallet->transactions[k - 1], tx)) continue;
                array_rm(wallet->transactions, k - 1);
                _LWWalletInsertTx(wallet, tx);
                break;
            }
            
            hashes[j++] = txHashes[i];
            if (LWSetContains(wallet->pendingTx, tx) || LWSetContains(wallet->invalidTx, tx)) needsUpdate = 1;
        }
        else if (blockHeight != TX_UNCONFIRMED) { // remove and free confirmed non-wallet tx
            LWSetRemove(wallet->allTx, tx);
            LWTransactionFree(tx);
        }
    }
    
    if (needsUpdate) _LWWalletUpdateBalance(wallet);
    pthread_mutex_unlock(&wallet->lock);
    if (needsUpdate && wallet->balanceChanged) {
        wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
    }
    if (j > 0 && wallet->txUpdated) wallet->txUpdated(wallet->callbackInfo, hashes, j, blockHeight, timestamp);
}

// marks all transactions confirmed after blockHeight as unconfirmed (useful for chain re-orgs)
void LWWalletSetTxUnconfirmedAfter(LWWallet *wallet, uint32_t blockHeight)
{
    size_t i, j, count;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    wallet->blockHeight = blockHeight;
    count = i = array_count(wallet->transactions);
    while (i > 0 && wallet->transactions[i - 1]->blockHeight > blockHeight) i--;
    count -= i;

    UInt256 hashes[count];

    for (j = 0; j < count; j++) {
        wallet->transactions[i + j]->blockHeight = TX_UNCONFIRMED;
        hashes[j] = wallet->transactions[i + j]->txHash;
    }
    
    if (count > 0) _LWWalletUpdateBalance(wallet);
    pthread_mutex_unlock(&wallet->lock);
    if (count > 0 && wallet->balanceChanged) {
        wallet->balanceChanged(wallet->callbackInfo, wallet->balance);
    }
    if (count > 0 && wallet->txUpdated) wallet->txUpdated(wallet->callbackInfo, hashes, count, TX_UNCONFIRMED, 0);
}

// returns the amount received by the wallet from the transaction (total outputs to change and/or receive addresses)
uint64_t LWWalletAmountReceivedFromTx(LWWallet *wallet, const LWTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    // TODO: don't include outputs below TX_MIN_OUTPUT_AMOUNT
    for (size_t i = 0; tx && i < tx->outCount; i++) {
        if (LWSetContains(wallet->allAddrs, tx->outputs[i].address)) amount += tx->outputs[i].amount;
    }
    
    pthread_mutex_unlock(&wallet->lock);
    return amount;
}

// returns the amount sent from the wallet by the trasaction (total wallet outputs consumed, change and fee included)
uint64_t LWWalletAmountSentByTx(LWWallet *wallet, const LWTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    for (size_t i = 0; tx && i < tx->inCount; i++) {
        LWTransaction *t = LWSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;
        
        if (t && n < t->outCount && LWSetContains(wallet->allAddrs, t->outputs[n].address)) {
            amount += t->outputs[n].amount;
        }
    }
    
    pthread_mutex_unlock(&wallet->lock);
    return amount;
}

// returns the fee for the given transaction if all its inputs are from wallet transactions, UINT64_MAX otherwise
uint64_t LWWalletFeeForTx(LWWallet *wallet, const LWTransaction *tx)
{
    uint64_t amount = 0;
    
    assert(wallet != NULL);
    assert(tx != NULL);
    pthread_mutex_lock(&wallet->lock);
    
    for (size_t i = 0; tx && i < tx->inCount && amount != UINT64_MAX; i++) {
        LWTransaction *t = LWSetGet(wallet->allTx, &tx->inputs[i].txHash);
        uint32_t n = tx->inputs[i].index;
        
        if (t && n < t->outCount) {
            amount += t->outputs[n].amount;
        }
        else amount = UINT64_MAX;
    }
    
    pthread_mutex_unlock(&wallet->lock);
    
    for (size_t i = 0; tx && i < tx->outCount && amount != UINT64_MAX; i++) {
        amount -= tx->outputs[i].amount;
    }
    
    return amount;
}

// historical wallet balance after the given transaction, or current balance if transaction is not registered in wallet
uint64_t LWWalletBalanceAfterTx(LWWallet *wallet, const LWTransaction *tx)
{
    uint64_t balance;
    
    assert(wallet != NULL);
    assert(tx != NULL && LWTransactionIsSigned(tx));
    pthread_mutex_lock(&wallet->lock);
    balance = wallet->balance;
    
    for (size_t i = array_count(wallet->transactions); tx && i > 0; i--) {
        if (! LWTransactionEq(tx, wallet->transactions[i - 1])) continue;
        balance = wallet->balanceHist[i - 1];
        break;
    }

    pthread_mutex_unlock(&wallet->lock);
    return balance;
}

// fee that will be added for a transaction of the given size in bytes
uint64_t LWWalletFeeForTxSize(LWWallet *wallet, size_t size)
{
    uint64_t fee;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    fee = _txFee(wallet->feePerKb, size);
    pthread_mutex_unlock(&wallet->lock);
    return fee;
}

// fee that will be added for a transaction of the given amount
uint64_t LWWalletFeeForTxAmount(LWWallet *wallet, uint64_t amount)
{
    static const uint8_t dummyScript[] = { OP_DUP, OP_HASH160, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0, 0, OP_EQUALVERIFY, OP_CHECKSIG };
    LWTxOutput o = LW_TX_OUTPUT_NONE;
    LWTransaction *tx;
    uint64_t fee = 0, maxAmount = 0;
    
    assert(wallet != NULL);
    assert(amount > 0);
    maxAmount = LWWalletMaxOutputAmount(wallet);
    o.amount = (amount < maxAmount) ? amount : maxAmount;
    LWTxOutputSetScript(&o, dummyScript, sizeof(dummyScript)); // unspendable dummy scriptPubKey
    tx = LWWalletCreateTxForOutputs(wallet, &o, 1);

    if (tx) {
        fee = LWWalletFeeForTx(wallet, tx);
        LWTransactionFree(tx);
    }
    
    return fee;
}

// outputs below this amount are uneconomical due to fees (TX_MIN_OUTPUT_AMOUNT is the absolute minimum output amount)
uint64_t LWWalletMinOutputAmount(LWWallet *wallet)
{
    uint64_t amount;
    
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    amount = (TX_MIN_OUTPUT_AMOUNT*wallet->feePerKb + MIN_FEE_PER_KB - 1)/MIN_FEE_PER_KB;
    pthread_mutex_unlock(&wallet->lock);
    return (amount > TX_MIN_OUTPUT_AMOUNT) ? amount : TX_MIN_OUTPUT_AMOUNT;
}

// maximum amount that can be sent from the wallet to a single address after fees
uint64_t LWWalletMaxOutputAmount(LWWallet *wallet)
{
    LWTransaction *tx;
    LWUTXO *o;
    uint64_t fee, amount = 0;
    size_t i, txSize, cpfpSize = 0, inCount = 0;

    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);

    for (i = array_count(wallet->utxos); i > 0; i--) {
        o = &wallet->utxos[i - 1];
        tx = LWSetGet(wallet->allTx, &o->hash);
        if (! tx || o->n >= tx->outCount) continue;
        inCount++;
        amount += tx->outputs[o->n].amount;
        
//        // size of unconfirmed, non-change inputs for child-pays-for-parent fee
//        // don't include parent tx with more than 10 inputs or 10 outputs
//        if (tx->blockHeight == TX_UNCONFIRMED && tx->inCount <= 10 && tx->outCount <= 10 &&
//            ! _LWWalletTxIsSend(wallet, tx)) cpfpSize += LWTransactionSize(tx);
    }

    txSize = 8 + LWVarIntSize(inCount) + TX_INPUT_SIZE*inCount + LWVarIntSize(2) + TX_OUTPUT_SIZE*2;
    fee = _txFee(wallet->feePerKb, txSize + cpfpSize);
    pthread_mutex_unlock(&wallet->lock);
    
    return (amount > fee) ? amount - fee : 0;
}

// frees memory allocated for wallet, and calls LWTransactionFree() for all registered transactions
void LWWalletFree(LWWallet *wallet)
{
    assert(wallet != NULL);
    pthread_mutex_lock(&wallet->lock);
    LWSetFree(wallet->allAddrs);
    LWSetFree(wallet->usedAddrs);
    LWSetFree(wallet->allTx);
    LWSetFree(wallet->invalidTx);
    LWSetFree(wallet->pendingTx);
    LWSetFree(wallet->spentOutputs);
    array_free(wallet->internalChain);
    array_free(wallet->externalChain);
    array_free(wallet->balanceHist);

    for (size_t i = array_count(wallet->transactions); i > 0; i--) {
        LWTransactionFree(wallet->transactions[i - 1]);
    }

    array_free(wallet->transactions);
    array_free(wallet->utxos);
    pthread_mutex_unlock(&wallet->lock);
    pthread_mutex_destroy(&wallet->lock);
    free(wallet);
}

// returns the given amount (in satoshis) in local currency units (i.e. pennies, pence)
// price is local currency units per bitcoin
int64_t LWLocalAmount(int64_t amount, double price)
{
    int64_t localAmount = llabs(amount)*price/SATOSHIS;
    
    // if amount is not 0, but is too small to be represented in local currency, return minimum non-zero localAmount
    if (localAmount == 0 && amount != 0) localAmount = 1;
    return (amount < 0) ? -localAmount : localAmount;
}

// returns the given local currency amount in satoshis
// price is local currency units (i.e. pennies, pence) per bitcoin
int64_t LWBitcoinAmount(int64_t localAmount, double price)
{
    int overflowbits = 0;
    int64_t p = 10, min, max, amount = 0, lamt = llabs(localAmount);

    if (lamt != 0 && price > 0) {
        while (lamt + 1 > INT64_MAX/SATOSHIS) lamt /= 2, overflowbits++; // make sure we won't overflow an int64_t
        min = lamt*SATOSHIS/price; // minimum amount that safely matches localAmount
        max = (lamt + 1)*SATOSHIS/price - 1; // maximum amount that safely matches localAmount
        amount = (min + max)/2; // average min and max
        while (overflowbits > 0) lamt *= 2, min *= 2, max *= 2, amount *= 2, overflowbits--;
        
        if (amount >= MAX_MONEY) return (localAmount < 0) ? -MAX_MONEY : MAX_MONEY;
        while ((amount/p)*p >= min && p <= INT64_MAX/10) p *= 10; // lowest decimal precision matching localAmount
        p /= 10;
        amount = (amount/p)*p;
    }
    
    return (localAmount < 0) ? -amount : amount;
}
