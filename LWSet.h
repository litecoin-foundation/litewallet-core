//
//  LWSet.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWSet_h
#define LWSet_h

#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LWSetStruct LWSet;

// retruns a newly allocated empty set that must be freed by calling LWSetFree()
// size_t hash(const void *) is a function that returns a hash value for a given set item
// int eq(const void *, const void *) is a function that returns true if two set items are equal
// any two items that are equal must also have identical hash values
// capacity is the initial number of items the set can hold, which will be auto-increased as needed
LWSet *LWSetNew(size_t (*hash)(const void *), int (*eq)(const void *, const void *), size_t capacity);

// adds given item to set or replaces an equivalent existing item and returns item replaced if any
void *LWSetAdd(LWSet *set, void *item);

// removes item equivalent to given item from set and returns item removed if any
void *LWSetRemove(LWSet *set, const void *item);

// removes all items from set
void LWSetClear(LWSet *set);

// returns the number of items in set
size_t LWSetCount(const LWSet *set);

// true if an item equivalant to the given item is contained in set
int LWSetContains(const LWSet *set, const void *item);

// true if any items in otherSet are contained in set
int LWSetIntersects(const LWSet *set, const LWSet *otherSet);

// returns member item from set equivalent to given item, or NULL if there is none
void *LWSetGet(const LWSet *set, const void *item);

// interates over set and returns the next item after previous, or NULL if no more items are available
// if previous is NULL, an initial item is returned
void *LWSetIterate(const LWSet *set, const void *previous);

// writes up to count items from set to allItems and returns number of items written
size_t LWSetAll(const LWSet *set, void *allItems[], size_t count);

// calls apply() with each item in set
void LWSetApply(const LWSet *set, void *info, void (*apply)(void *info, void *item));

// adds or replaces items from otherSet into set
void LWSetUnion(LWSet *set, const LWSet *otherSet);

// removes items contained in otherSet from set
void LWSetMinus(LWSet *set, const LWSet *otherSet);

// removes items not contained in otherSet from set
void LWSetIntersect(LWSet *set, const LWSet *otherSet);

// frees memory allocated for set
void LWSetFree(LWSet *set);

#ifdef __cplusplus
}
#endif

#endif // LWSet_h
