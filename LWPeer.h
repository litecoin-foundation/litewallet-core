//
//  LWPeer.h
//  https://github.com/litecoin-foundation/litewallet-core#readme#OpenSourceLink

#ifndef LWPeer_h
#define LWPeer_h

#include "LWTransaction.h"
#include "LWMerkleBlock.h"
#include "LWAddress.h"
#include "LWInt.h"
#include <stddef.h>
#include <inttypes.h>

#define peer_log(peer, ...) _peer_log("%s:%"PRIu16" " _va_first(__VA_ARGS__, NULL) "\n", LWPeerHost(peer),\
                                      (peer)->port, _va_rest(__VA_ARGS__, NULL))
#define _va_first(first, ...) first
#define _va_rest(first, ...) __VA_ARGS__

#if defined(TARGET_OS_MAC)
#include <Foundation/Foundation.h>
#define _peer_log(...) NSLog(__VA_ARGS__)
#elif defined(__ANDROID__)
#include <android/log.h>
#define _peer_log(...) __android_log_print(ANDROID_LOG_INFO, "bread", __VA_ARGS__)
#else
#include <stdio.h>
#define _peer_log(...) printf(__VA_ARGS__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SERVICES_NODE_NETWORK 0x01 // services value indicating a node carries full blocks, not just headers
#define SERVICES_NODE_BLOOM   0x04 // BIP111: https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki
#define SERVICES_NODE_BCASH   0x20 // https://github.com/Bitcoin-UAHF/spec/blob/master/uahf-technical-spec.md
    
#define LW_VERSION "0.1"
#define USER_AGENT "/litewallet:" LW_VERSION "/"

// explanation of message types at: https://en.bitcoin.it/wiki/Protocol_specification
#define MSG_VERSION     "version"
#define MSG_VERACK      "verack"
#define MSG_ADDR        "addr"
#define MSG_INV         "inv"
#define MSG_GETDATA     "getdata"
#define MSG_NOTFOUND    "notfound"
#define MSG_GETBLOCKS   "getblocks"
#define MSG_GETHEADERS  "getheaders"
#define MSG_TX          "tx"
#define MSG_BLOCK       "block"
#define MSG_HEADERS     "headers"
#define MSG_GETADDR     "getaddr"
#define MSG_MEMPOOL     "mempool"
#define MSG_PING        "ping"
#define MSG_PONG        "pong"
#define MSG_FILTERLOAD  "filterload"
#define MSG_FILTERADD   "filteradd"
#define MSG_FILTERCLEAR "filterclear"
#define MSG_MERKLEBLOCK "merkleblock"
#define MSG_ALERT       "alert"
#define MSG_REJECT      "reject"   // described in BIP61: https://github.com/bitcoin/bips/blob/master/bip-0061.mediawiki
#define MSG_FEEFILTER   "feefilter"// described in BIP133 https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki

#define REJECT_INVALID     0x10 // transaction is invalid for some reason (invalid signature, output value > input, etc)
#define REJECT_SPENT       0x12 // an input is already spent
#define REJECT_NONSTANDARD 0x40 // not mined/relayed because it is "non-standard" (type or version unknown by server)
#define REJECT_DUST        0x41 // one or more output amounts are below the 'dust' threshold
#define REJECT_LOWFEE      0x42 // transaction does not have enough fee/priority to be relayed or mined

typedef enum {
    LWPeerStatusDisconnected = 0,
    LWPeerStatusConnecting,
    LWPeerStatusConnected
} LWPeerStatus;

typedef struct {
    UInt128 address; // IPv6 address of peer
    uint16_t port; // port number for peer connection
    uint64_t services; // bitcoin network services supported by peer
    uint64_t timestamp; // timestamp reported by peer
    uint8_t flags; // scratch variable
} LWPeer;

#define LW_PEER_NONE ((LWPeer) { UINT128_ZERO, 0, 0, 0, 0 })

// NOTE: LWPeer functions are not thread-safe

// returns a newly allocated LWPeer struct that must be freed by calling LWPeerFree()
LWPeer *LWPeerNew(uint32_t magicNumber);

// info is a void pointer that will be passed along with each callback call
// void connected(void *) - called when peer handshake completes successfully
// void disconnected(void *, int) - called when peer connection is closed, error is an errno.h code
// void relayedPeers(void *, const LWPeer[], size_t) - called when an "addr" message is received from peer
// void relayedTx(void *, LWTransaction *) - called when a "tx" message is received from peer
// void hasTx(void *, UInt256 txHash) - called when an "inv" message with an already-known tx hash is received from peer
// void rejectedTx(void *, UInt256 txHash, uint8_t) - called when a "reject" message is received from peer
// void relayedBlock(void *, LWMerkleBlock *) - called when a "merkleblock" or "headers" message is received from peer
// void notfound(void *, const UInt256[], size_t, const UInt256[], size_t) - called when "notfound" message is received
// LWTransaction *requestedTx(void *, UInt256) - called when "getdata" message with a tx hash is received from peer
// int networkIsReachable(void *) - must return true when networking is available, false otherwise
// void threadCleanup(void *) - called before a thread terminates to faciliate any needed cleanup
void LWPeerSetCallbacks(LWPeer *peer, void *info,
                        void (*connected)(void *info),
                        void (*disconnected)(void *info, int error),
                        void (*relayedPeers)(void *info, const LWPeer peers[], size_t peersCount),
                        void (*relayedTx)(void *info, LWTransaction *tx),
                        void (*hasTx)(void *info, UInt256 txHash),
                        void (*rejectedTx)(void *info, UInt256 txHash, uint8_t code),
                        void (*relayedBlock)(void *info, LWMerkleBlock *block),
                        void (*notfound)(void *info, const UInt256 txHashes[], size_t txCount,
                                         const UInt256 blockHashes[], size_t blockCount),
                        void (*setFeePerKb)(void *info, uint64_t feePerKb),
                        LWTransaction *(*requestedTx)(void *info, UInt256 txHash),
                        int (*networkIsReachable)(void *info),
                        void (*threadCleanup)(void *info));

// set earliestKeyTime to wallet creation time in order to speed up initial sync
void LWPeerSetEarliestKeyTime(LWPeer *peer, uint32_t earliestKeyTime);

// call this when local best block height changes (helps detect tarpit nodes)
void LWPeerSetCurrentBlockHeight(LWPeer *peer, uint32_t currentBlockHeight);

// current connection status
LWPeerStatus LWPeerConnectStatus(LWPeer *peer);

// open connection to peer and perform handshake
void LWPeerConnect(LWPeer *peer);

// close connection to peer
void LWPeerDisconnect(LWPeer *peer);

// call this to (re)schedule a disconnect in the given number of seconds, or < 0 to cancel (useful for sync timeout)
void LWPeerScheduleDisconnect(LWPeer *peer, double seconds);

// set this to true when wallet addresses need to be added to bloom filter
void LWPeerSetNeedsFilterUpdate(LWPeer *peer, int needsFilterUpdate);

// display name of peer address
const char *LWPeerHost(LWPeer *peer);

// connected peer version number
uint32_t LWPeerVersion(LWPeer *peer);

// connected peer user agent string
const char *LWPeerUserAgent(LWPeer *peer);

// best block height reported by connected peer
uint32_t LWPeerLastBlock(LWPeer *peer);

// minimum tx fee rate peer will accept
uint64_t LWPeerFeePerKb(LWPeer *peer);

// average ping time for connected peer
double LWPeerPingTime(LWPeer *peer);

// sends a bitcoin protocol message to peer
void LWPeerSendMessage(LWPeer *peer, const uint8_t *msg, size_t msgLen, const char *type);
void LWPeerSendFilterload(LWPeer *peer, const uint8_t *filter, size_t filterLen);
void LWPeerSendMempool(LWPeer *peer, const UInt256 knownTxHashes[], size_t knownTxCount, void *info,
                       void (*completionCallback)(void *info, int success));
void LWPeerSendGetheaders(LWPeer *peer, const UInt256 locators[], size_t locatorsCount, UInt256 hashStop);
void LWPeerSendGetblocks(LWPeer *peer, const UInt256 locators[], size_t locatorsCount, UInt256 hashStop);
void LWPeerSendInv(LWPeer *peer, const UInt256 txHashes[], size_t txCount);
void LWPeerSendGetdata(LWPeer *peer, const UInt256 txHashes[], size_t txCount, const UInt256 blockHashes[],
                       size_t blockCount);
void LWPeerSendGetaddr(LWPeer *peer);
void LWPeerSendPing(LWPeer *peer, void *info, void (*pongCallback)(void *info, int success));

// useful to get additional tx after a bloom filter update
void LWPeerRerequestBlocks(LWPeer *peer, UInt256 fromBlock);

// returns a hash value for peer suitable for use in a hashtable
inline static size_t LWPeerHash(const void *peer)
{
    uint32_t address = ((const LWPeer *)peer)->address.u32[3], port = ((const LWPeer *)peer)->port;

    // (((FNV_OFFSET xor address)*FNV_PRIME) xor port)*FNV_PRIME
    return (size_t)((((0x811C9dc5 ^ address)*0x01000193) ^ port)*0x01000193);
}

// true if a and b have the same address and port
inline static int LWPeerEq(const void *peer, const void *otherPeer)
{
    return (peer == otherPeer ||
            (UInt128Eq(((const LWPeer *)peer)->address, ((const LWPeer *)otherPeer)->address) &&
             ((const LWPeer *)peer)->port == ((const LWPeer *)otherPeer)->port));
}

// frees memory allocated for peer
void LWPeerFree(LWPeer *peer);

#ifdef __cplusplus
}
#endif

#endif // LWPeer_h
