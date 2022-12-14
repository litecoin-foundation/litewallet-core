//
//  LWBloomFilter.h
//  https://github.com/litecoin-foundation/litewallet-core#readme#OpenSourceLink

#ifndef LWBloomFilter_h
#define LWBloomFilter_h

#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// bloom filters are explained in BIP37: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki

#define BLOOM_DEFAULT_FALSEPOSITIVE_RATE 0.0005 // use 0.00005 for less data, 0.001 for good anonymity
#define BLOOM_REDUCED_FALSEPOSITIVE_RATE 0.00005
#define BLOOM_UPDATE_NONE                0
#define BLOOM_UPDATE_ALL                 1
#define BLOOM_UPDATE_P2PUBKEY_ONLY       2
#define BLOOM_MAX_FILTER_LENGTH          36000 // this allows for 10,000 elements with a <0.0001% false positive rate

typedef struct {
    uint8_t *filter;
    size_t length;
    uint32_t hashFuncs;
    size_t elemCount;
    uint32_t tweak;
    uint8_t flags;
} LWBloomFilter;

// a bloom filter that matches everything is useful if a full node wants to use the filtered block protocol, which
// doesn't send transactions with blocks if the receiving node already received the tx prior to its inclusion in the
// block, allowing a full node to operate while using about half the network traffic
#define LW_BLOOM_FILTER_FULL ((LWBloomFilter) { &((struct { uint8_t u; }) { 0xff }).u, 1, 0, 0, 0, BLOOM_UPDATE_NONE })

// returns a newly allocated bloom filter struct that must be freed by calling LWBloomFilterFree()
LWBloomFilter *LWBloomFilterNew(double falsePositiveRate, size_t elemCount, uint32_t tweak, uint8_t flags);

// buf must contain a serialized filter
// returns a bloom filter struct that must be freed by calling LWBloomFilterFree()
LWBloomFilter *LWBloomFilterParse(const uint8_t *buf, size_t bufLen);

// returns number of bytes written to buf, or total bufLen needed if buf is NULL
size_t LWBloomFilterSerialize(const LWBloomFilter *filter, uint8_t *buf, size_t bufLen);

// true if data is matched by filter
int LWBloomFilterContainsData(const LWBloomFilter *filter, const uint8_t *data, size_t dataLen);

// add data to filter
void LWBloomFilterInsertData(LWBloomFilter *filter, const uint8_t *data, size_t dataLen);

// frees memory allocated for filter
void LWBloomFilterFree(LWBloomFilter *filter);

#ifdef __cplusplus
}
#endif

#endif // LWBloomFilter_h
