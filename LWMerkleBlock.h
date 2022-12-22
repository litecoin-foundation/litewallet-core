//
//  LWMerkleBlock.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md


#ifndef LWMerkleBlock_h
#define LWMerkleBlock_h

#include "LWInt.h"
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLOCK_DIFFICULTY_INTERVAL 2016 // number of blocks between difficulty target adjustments
#define BLOCK_UNKNOWN_HEIGHT      INT32_MAX
#define BLOCK_MAX_TIME_DRIFT      (2*60*60) // the furthest in the future a block is allowed to be timestamped

typedef struct {
    UInt256 blockHash;
    UInt256 powHash;
    uint32_t version;
    UInt256 prevBlock;
    UInt256 merkleRoot;
    uint32_t timestamp; // time interval since unix epoch
    uint32_t target;
    uint32_t nonce;
    uint32_t totalTx;
    UInt256 *hashes;
    size_t hashesCount;
    uint8_t *flags;
    size_t flagsLen;
    uint32_t height;
} LWMerkleBlock;

#define LW_MERKLE_BLOCK_NONE\
    ((LWMerkleBlock) { UINT256_ZERO, 0, UINT256_ZERO, UINT256_ZERO, 0, 0, 0, 0, NULL, 0, NULL, 0, 0 })

// returns a newly allocated merkle block struct that must be freed by calling LWMerkleBlockFree()
LWMerkleBlock *LWMerkleBlockNew(void);

// returns a deep copy of block and that must be freed by calling LWMerkleBlockFree()
LWMerkleBlock *LWMerkleBlockCopy(const LWMerkleBlock *block);

// buf must contain either a serialized merkleblock or header
// returns a merkle block struct that must be freed by calling LWMerkleBlockFree()
LWMerkleBlock *LWMerkleBlockParse(const uint8_t *buf, size_t bufLen);

// returns number of bytes written to buf, or total bufLen needed if buf is NULL (block->height is not serialized)
size_t LWMerkleBlockSerialize(const LWMerkleBlock *block, uint8_t *buf, size_t bufLen);

// populates txHashes with the matched tx hashes in the block
// returns number of tx hashes written, or the total hashesCount needed if txHashes is NULL
size_t LWMerkleBlockTxHashes(const LWMerkleBlock *block, UInt256 *txHashes, size_t hashesCount);

// sets the hashes and flags fields for a block created with LWMerkleBlockNew()
void LWMerkleBlockSetTxHashes(LWMerkleBlock *block, const UInt256 hashes[], size_t hashesCount,
                              const uint8_t *flags, size_t flagsLen);

// true if merkle tree and timestamp are valid, and proof-of-work matches the stated difficulty target
// NOTE: this only checks if the block difficulty matches the difficulty target in the header, it does not check if the
// target is correct for the block's height in the chain - use LWMerkleBlockVerifyDifficulty() for that
int LWMerkleBlockIsValid(const LWMerkleBlock *block, uint32_t currentTime);

// true if the given tx hash is known to be included in the block
int LWMerkleBlockContainsTxHash(const LWMerkleBlock *block, UInt256 txHash);

// verifies the block difficulty target is correct for the block's position in the chain
// transitionTime is the timestamp of the block at the previous difficulty transition
// transitionTime may be 0 if block->height is not a multiple of BLOCK_DIFFICULTY_INTERVAL
int LWMerkleBlockVerifyDifficulty(const LWMerkleBlock *block, const LWMerkleBlock *previous, uint32_t transitionTime);

// returns a hash value for block suitable for use in a hashtable
inline static size_t LWMerkleBlockHash(const void *block)
{
    return (size_t)((const LWMerkleBlock *)block)->blockHash.u32[0];
}

// true if block and otherBlock have equal blockHash values
inline static int LWMerkleBlockEq(const void *block, const void *otherBlock)
{
    return (block == otherBlock ||
            UInt256Eq(((const LWMerkleBlock *)block)->blockHash, ((const LWMerkleBlock *)otherBlock)->blockHash));
}

// frees memory allocated for block
void LWMerkleBlockFree(LWMerkleBlock *block);

#ifdef __cplusplus
}
#endif

#endif // LWMerkleBlock_h
