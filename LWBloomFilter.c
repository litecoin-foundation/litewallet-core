//
//  LWBloomFilter.c
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md


#include "LWBloomFilter.h"
#include "LWCrypto.h"
#include "LWAddress.h"
#include "LWInt.h"
#include <stdlib.h>
#include <float.h>
#include <math.h>
#include <assert.h>

#define BLOOM_MAX_HASH_FUNCS 50

inline static uint32_t _LWBloomFilterHash(const LWBloomFilter *filter, const uint8_t *data, size_t dataLen,
                                          uint32_t hashNum)
{
    return LWMurmur3_32(data, dataLen, hashNum*0xfba4c795 + filter->tweak) % (filter->length*8);
}

// returns a newly allocated bloom filter struct that must be freed by calling LWBloomFilterFree()
LWBloomFilter *LWBloomFilterNew(double falsePositiveRate, size_t elemCount, uint32_t tweak, uint8_t flags)
{
    LWBloomFilter *filter = calloc(1, sizeof(*filter));

    assert(filter != NULL);
    filter->length = (falsePositiveRate < DBL_EPSILON) ? BLOOM_MAX_FILTER_LENGTH :
                     (-1.0/(M_LN2*M_LN2))*elemCount*log(falsePositiveRate)/8.0;
    if (filter->length > BLOOM_MAX_FILTER_LENGTH) filter->length = BLOOM_MAX_FILTER_LENGTH;
    if (filter->length < 1) filter->length = 1;
    filter->filter = calloc(filter->length, sizeof(*(filter->filter)));
    assert(filter->filter != NULL);
    filter->hashFuncs = ((filter->length*8.0)/elemCount)*M_LN2;
    if (filter->hashFuncs > BLOOM_MAX_HASH_FUNCS) filter->hashFuncs = BLOOM_MAX_HASH_FUNCS;
    filter->tweak = tweak;
    filter->flags = flags;

    if (! filter->filter) {
        free(filter);
        filter = NULL;
    }

    return filter;
}

// buf must contain a serialized filter
// returns a bloom filter struct that must be freed by calling LWBloomFilterFree()
LWBloomFilter *LWBloomFilterParse(const uint8_t *buf, size_t bufLen)
{
    LWBloomFilter *filter = calloc(1, sizeof(*filter));
    size_t off = 0, len = 0;
    
    assert(filter != NULL);
    assert(buf != NULL || bufLen == 0);
    
    if (buf) {
        filter->length = (size_t)LWVarInt(&buf[off], (off <= bufLen ? bufLen - off : 0), &len);
        off += len;
        filter->filter = (filter->length <= BLOOM_MAX_FILTER_LENGTH && off + filter->length <= bufLen) ?
                         malloc(filter->length) : NULL;
        if (filter->filter) memcpy(filter->filter, &buf[off], filter->length);
        off += filter->length;
        filter->hashFuncs = (off + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[off]) : 0;
        off += sizeof(uint32_t);
        filter->tweak = (off + sizeof(uint32_t) <= bufLen) ? UInt32GetLE(&buf[off]) : 0;
        off += sizeof(uint32_t);
        filter->flags = (off + sizeof(uint8_t) <= bufLen) ? buf[off] : 0;
        off += sizeof(uint8_t);
    }
    
    if (! filter->filter) {
        free(filter);
        filter = NULL;
    }

    return filter;
}

// returns number of bytes written to buf, or total bufLen needed if buf is NULL
size_t LWBloomFilterSerialize(const LWBloomFilter *filter, uint8_t *buf, size_t bufLen)
{
    size_t off = 0,
           len = LWVarIntSize(filter->length) + filter->length + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t);
    
    assert(filter != NULL);
    assert(buf != NULL || bufLen == 0);
    
    if (buf && len <= bufLen) {
        off += LWVarIntSet(&buf[off], (off <= bufLen ? bufLen - off : 0), filter->length);
        memcpy(&buf[off], filter->filter, filter->length);
        off += filter->length;
        UInt32SetLE(&buf[off], filter->hashFuncs);
        off += sizeof(uint32_t);
        UInt32SetLE(&buf[off], filter->tweak);
        off += sizeof(uint32_t);
        buf[off] = filter->flags;
        off += sizeof(uint8_t);
    }
    
    return (! buf || len <= bufLen) ? len : 0;
}

// true if data is matched by filter
int LWBloomFilterContainsData(const LWBloomFilter *filter, const uint8_t *data, size_t dataLen)
{
    uint32_t i, idx;
    
    assert(filter != NULL);
    assert(data != NULL || dataLen == 0);
    
    for (i = 0; data && i < filter->hashFuncs; i++) {
        idx = _LWBloomFilterHash(filter, data, dataLen, i);
        if (! (filter->filter[idx >> 3] & (1 << (7 & idx)))) return 0;
    }
    
    return (data) ? 1 : 0;
}

// add data to filter
void LWBloomFilterInsertData(LWBloomFilter *filter, const uint8_t *data, size_t dataLen)
{
    uint32_t i, idx;
    
    assert(filter != NULL);
    assert(data != NULL || dataLen == 0);
    
    for (i = 0; data && i < filter->hashFuncs; i++) {
        idx = _LWBloomFilterHash(filter, data, dataLen, i);
        filter->filter[idx >> 3] |= (1 << (7 & idx));
    }
    
    if (data) filter->elemCount++;
}

// frees memory allocated for filter
void LWBloomFilterFree(LWBloomFilter *filter)
{
    assert(filter != NULL);
    if (filter->filter) free(filter->filter);
    free(filter);
}
