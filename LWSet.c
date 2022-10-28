//
//  LWSet.c
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#include "LWSet.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// linear probed hashtable for good cache performance, maximum load factor is 2/3

static const size_t tableSizes[] = { // starting with 1, multiply by 3/2, round up, then find next largest prime
    1, 3, 7, 13, 23, 37, 59, 97, 149, 227, 347, 523, 787, 1187, 1783, 2677, 4019, 6037, 9059, 13591,
    20389, 30593, 45887, 68863, 103307, 154981, 232487, 348739, 523129, 784697, 1177067, 1765609,
    2648419, 3972643, 5958971, 8938469, 13407707, 20111563, 30167359, 45251077, 67876637, 101814991,
    152722489, 229083739, 343625629, 515438447, 773157683, 1159736527, 1739604799, 2609407319, 3914111041
};

#define TABLE_SIZES_LEN (sizeof(tableSizes)/sizeof(*tableSizes))

struct LWSetStruct {
    void **table; // hashtable
    size_t size; // number of buckets in table
    size_t itemCount; // number of items in set
    size_t (*hash)(const void *); // hash function
    int (*eq)(const void *, const void *); // equality function
};

static void _LWSetInit(LWSet *set, size_t (*hash)(const void *), int (*eq)(const void *, const void *), size_t capacity)
{
    assert(set != NULL);
    assert(hash != NULL);
    assert(eq != NULL);
    assert(capacity >= 0);

    size_t i = 0;
    
    while (i < TABLE_SIZES_LEN && tableSizes[i] < capacity) i++;

    if (i + 1 < TABLE_SIZES_LEN) { // use next larger table size to keep load factor below 2/3 at capacity
        set->table = calloc(tableSizes[i + 1], sizeof(void *));
        assert(set->table != NULL);
        set->size = tableSizes[i + 1];
    }
    
    set->itemCount = 0;
    set->hash = hash;
    set->eq = eq;
}

// retruns a newly allocated empty set that must be freed by calling LWSetFree()
// size_t hash(const void *) is a function that returns a hash value for a given set item
// int eq(const void *, const void *) is a function that returns true if two set items are equal
// any two items that are equal must also have identical hash values
// capacity is the maximum estimated number of items the set will need to hold
LWSet *LWSetNew(size_t (*hash)(const void *), int (*eq)(const void *, const void *), size_t capacity)
{
    LWSet *set = calloc(1, sizeof(*set));
    
    assert(set != NULL);
    _LWSetInit(set, hash, eq, capacity);
    return set;
}

// rebuilds hashtable to hold up to capacity items
static void _LWSetGrow(LWSet *set, size_t capacity)
{
    LWSet newSet;
    
    _LWSetInit(&newSet, set->hash, set->eq, capacity);
    LWSetUnion(&newSet, set);
    free(set->table);
    set->table = newSet.table;
    set->size = newSet.size;
    set->itemCount = newSet.itemCount;
}

// adds given item to set or replaces an equivalent existing item and returns item replaced if any
void *LWSetAdd(LWSet *set, void *item)
{
    assert(set != NULL);
    assert(item != NULL);
    
    size_t size = set->size;
    size_t i = set->hash(item) % size;
    void *t = set->table[i];

    while (t && t != item && ! set->eq(t, item)) { // probe for empty bucket
        i = (i + 1) % size;
        t = set->table[i];
    }

    if (! t) set->itemCount++;
    set->table[i] = item;
    if (set->itemCount > ((size + 2)/3)*2) _LWSetGrow(set, size); // limit load factor to 2/3
    return t;
}

// removes item equivalent to given item from set and returns item removed if any
void *LWSetRemove(LWSet *set, const void *item)
{
    assert(set != NULL);
    assert(item != NULL);
    
    size_t size = set->size;
    size_t i = set->hash(item) % size;
    void *r = set->table[i], *t;

    while (r != item && r && ! set->eq(r, item)) { // probe for item
        i = (i + 1) % size;
        r = set->table[i];
    }
    
    if (r) {
        set->itemCount--;
        set->table[i] = NULL;
        i = (i + 1) % size;
        t = set->table[i];
        
        while (t) { // hashtable cleanup
            set->itemCount--;
            set->table[i] = NULL;
            LWSetAdd(set, t);
            i = (i + 1) % size;
            t = set->table[i];
        }
    }
    
    return r;
}

// removes all items from set
void LWSetClear(LWSet *set)
{
    assert(set != NULL);
    
    memset(set->table, 0, set->size*sizeof(*set->table));
    set->itemCount = 0;
}

// returns the number of items in set
size_t LWSetCount(const LWSet *set)
{
    assert(set != NULL);
    
    return set->itemCount;
}

// true if an item equivalant to the given item is contained in set
int LWSetContains(const LWSet *set, const void *item)
{
    return (LWSetGet(set, item) != NULL);
}

// true if any items in otherSet are contained in set
int LWSetIntersects(const LWSet *set, const LWSet *otherSet)
{
    assert(set != NULL);
    assert(otherSet != NULL);
    
    size_t i = 0, size = otherSet->size;
    void *t;
    
    while (i < size) {
        t = otherSet->table[i++];
        if (t && LWSetGet(set, t) != NULL) return 1;
    }
    
    return 0;
}

// returns member item from set equivalent to given item, or NULL if there is none
void *LWSetGet(const LWSet *set, const void *item)
{
    assert(set != NULL);
    assert(item != NULL);
    
    size_t size = set->size;
    size_t i = set->hash(item) % size;
    void *t = set->table[i];

    while (t != item && t && ! set->eq(t, item)) { // probe for item
        i = (i + 1) % size;
        t = set->table[i];
    }
    
    return t;
}

// interates over set and returns the next item after previous, or NULL if no more items are available
// if previous is NULL, an initial item is returned
void *LWSetIterate(const LWSet *set, const void *previous)
{
    assert(set != NULL);
    
    size_t i = 0, size = set->size;
    void *t, *r = NULL;
    
    if (previous != NULL) {
        i = set->hash(previous) % size;
        t = set->table[i];
        
        while (t != previous && t && ! set->eq(t, previous)) { // probe for item
            i = (i + 1) % size;
            t = set->table[i];
        }
    
        i++;
    }
    
    while (! r && i < size) r = set->table[i++];
    return r;
}

// writes up to count items from set to allItems and returns the number of items written
size_t LWSetAll(const LWSet *set, void *allItems[], size_t count)
{
    assert(set != NULL);
    assert(allItems != NULL || count == 0);
    assert(count >= 0);
    
    size_t i = 0, j = 0, size = set->size;
    void *t;
    
    while (i < size && j < count) {
        t = set->table[i++];
        if (t) allItems[j++] = t;
    }
    
    return j;
}

// calls apply() with each item in set
void LWSetApply(const LWSet *set, void *info, void (*apply)(void *info, void *item))
{
    assert(set != NULL);
    assert(apply != NULL);
    
    size_t i = 0, size = set->size;
    void *t;
    
    while (i < size) {
        t = set->table[i++];
        if (t) apply(info, t);
    }
}

// adds or replaces items from otherSet into set
void LWSetUnion(LWSet *set, const LWSet *otherSet)
{
    assert(set != NULL);
    assert(otherSet != NULL);
    
    size_t i = 0, size = otherSet->size;
    void *t;
    
    while (i < size) {
        t = otherSet->table[i++];
        if (t) LWSetAdd(set, t);
    }
}

// removes items contained in otherSet from set
void LWSetMinus(LWSet *set, const LWSet *otherSet)
{
    assert(set != NULL);
    assert(otherSet != NULL);

    size_t i = 0, size = otherSet->size;
    void *t;
    
    while (i < size) {
        t = otherSet->table[i++];
        if (t) LWSetRemove(set, t);
    }
}

// removes items not contained in otherSet from set
void LWSetIntersect(LWSet *set, const LWSet *otherSet)
{
    assert(set != NULL);
    assert(otherSet != NULL);

    size_t i = 0, size = set->size;
    void *t;
    
    while (i < size) {
        t = set->table[i];

        if (t && ! LWSetContains(otherSet, t)) {
            LWSetRemove(set, t);
        }
        else i++;
    }
}

// frees memory allocated for set
void LWSetFree(LWSet *set)
{
    assert(set != NULL);

    free(set->table);
    free(set);
}
