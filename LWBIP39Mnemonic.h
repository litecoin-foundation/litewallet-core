//
//  LWBIP39Mnemonic.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWBIP39Mnemonic_h
#define LWBIP39Mnemonic_h

#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// BIP39 is method for generating a deterministic wallet seed from a mnemonic phrase
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

#define BIP39_CREATION_TIME  1464739200 // oldest possible BIP39 phrase creation time, seconds after unix epoch
#define BIP39_WORDLIST_COUNT 2048       // number of words in a BIP39 wordlist

// returns number of bytes written to phrase including NULL terminator, or phraseLen needed if phrase is NULL
size_t LWBIP39Encode(char *phrase, size_t phraseLen, const char *wordList[], const uint8_t *data, size_t dataLen);

// returns number of bytes written to data, or dataLen needed if data is NULL
size_t LWBIP39Decode(uint8_t *data, size_t dataLen, const char *wordList[], const char *phrase);

// verifies that all phrase words are contained in wordlist and checksum is valid
int LWBIP39PhraseIsValid(const char *wordList[], const char *phrase);

// key64 must hold 64 bytes (512 bits), phrase and passphrase must be unicode NFKD normalized
// http://www.unicode.org/reports/tr15/#Norm_Forms
// BUG: does not currently support passphrases containing NULL characters
void LWBIP39DeriveKey(void *key64, const char *phrase, const char *passphrase);

#ifdef __cplusplus
}
#endif

#endif // LWBIP39Mnemonic_h
