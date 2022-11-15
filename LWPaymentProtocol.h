//
//  BRPaymentProtocol.h
//  https://github.com/litecoin-foundation/litewallet-core/blob/main/asis.md

#ifndef LWPaymentProtocol_h
#define LWPaymentProtocol_h

#include "LWTransaction.h"
#include "LWAddress.h"
#include "LWKey.h"
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// BIP70 payment protocol: https://github.com/bitcoin/bips/blob/master/bip-0070.mediawiki
// BIP75 payment protocol encryption: https://github.com/bitcoin/bips/blob/master/bip-0075.mediawiki

typedef struct {
    char *network; // "main" or "test", default is "main"
    LWTxOutput *outputs; // where to send payments, outputs[n].amount defaults to 0
    size_t outCount;
    uint64_t time; // request creation time, seconds since unix epoch, optional
    uint64_t expires; // when this request should be considered invalid, optional
    char *memo; // human-readable description of request for the customer, optional
    char *paymentURL; // url to send payment and get payment ack, optional
    uint8_t *merchantData; // arbitrary data to include in the payment message, optional
    size_t merchDataLen;
} LWPaymentProtocolDetails;

// returns a newly allocated details struct that must be freed by calling LWPaymentProtocolDetailsFree()
LWPaymentProtocolDetails *LWPaymentProtocolDetailsNew(const char *network, const LWTxOutput outputs[], size_t outCount,
                                                      uint64_t time, uint64_t expires, const char *memo,
                                                      const char *paymentURL, const uint8_t *merchantData,
                                                      size_t merchDataLen);

// buf must contain a serialized details struct
// returns a details struct that must be freed by calling LWPaymentProtocolDetailsFree()
LWPaymentProtocolDetails *LWPaymentProtocolDetailsParse(const uint8_t *buf, size_t bufLen);

// writes serialized details struct to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolDetailsSerialize(const LWPaymentProtocolDetails *details, uint8_t *buf, size_t bufLen);

// frees memory allocated for details struct
void LWPaymentProtocolDetailsFree(LWPaymentProtocolDetails *details);

typedef struct {
    uint32_t version; // default is 1
    char *pkiType; // none / x509+sha256 / x509+sha1, default is "none"
    uint8_t *pkiData; // depends on pkiType, optional
    size_t pkiDataLen;
    LWPaymentProtocolDetails *details; // required
    uint8_t *signature; // pki-dependent signature, optional
    size_t sigLen;
} LWPaymentProtocolRequest;

// returns a newly allocated request struct that must be freed by calling LWPaymentProtocolRequestFree()
LWPaymentProtocolRequest *LWPaymentProtocolRequestNew(uint32_t version, const char *pkiType, const uint8_t *pkiData,
                                                      size_t pkiDataLen, LWPaymentProtocolDetails *details,
                                                      const uint8_t *signature, size_t sigLen);

// buf must contain a serialized request struct
// returns a request struct that must be freed by calling LWPaymentProtocolRequestFree()
LWPaymentProtocolRequest *LWPaymentProtocolRequestParse(const uint8_t *buf, size_t bufLen);

// writes serialized request struct to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolRequestSerialize(const LWPaymentProtocolRequest *req, uint8_t *buf, size_t bufLen);

// writes the DER encoded certificate corresponding to index to cert
// returns the number of bytes written to cert, or the total certLen needed if cert is NULL
// returns 0 if index is out-of-bounds
size_t LWPaymentProtocolRequestCert(const LWPaymentProtocolRequest *req, uint8_t *cert, size_t certLen, size_t idx);

// writes the hash of the request to md needed to sign or verify the request
// returns the number of bytes written, or the total mdLen needed if md is NULL
size_t LWPaymentProtocolRequestDigest(LWPaymentProtocolRequest *req, uint8_t *md, size_t mdLen);

// frees memory allocated for request struct
void LWPaymentProtocolRequestFree(LWPaymentProtocolRequest *req);

typedef struct {
    uint8_t *merchantData; // from request->details->merchantData, optional
    size_t merchDataLen;
    LWTransaction **transactions; // array of signed LWTransaction struct references to satisfy outputs from details
    size_t txCount;
    LWTxOutput *refundTo; // where to send refunds, if a refund is necessary, refundTo[n].amount defaults to 0
    size_t refundToCount;
    char *memo; // human-readable message for the merchant, optional
} LWPaymentProtocolPayment;

// returns a newly allocated payment struct that must be freed by calling LWPaymentProtocolPaymentFree()
LWPaymentProtocolPayment *LWPaymentProtocolPaymentNew(const uint8_t *merchantData, size_t merchDataLen,
                                                      LWTransaction *transactions[], size_t txCount,
                                                      const uint64_t refundToAmounts[],
                                                      const LWAddress refundToAddresses[], size_t refundToCount,
                                                      const char *memo);

// buf must contain a serialized payment struct
// returns a payment struct that must be freed by calling LWPaymentProtocolPaymentFree()
LWPaymentProtocolPayment *LWPaymentProtocolPaymentParse(const uint8_t *buf, size_t bufLen);

// writes serialized payment struct to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolPaymentSerialize(const LWPaymentProtocolPayment *payment, uint8_t *buf, size_t bufLen);

// frees memory allocated for payment struct (does not call LWTransactionFree() on transactions)
void LWPaymentProtocolPaymentFree(LWPaymentProtocolPayment *payment);

typedef struct {
    LWPaymentProtocolPayment *payment; // payment message that triggered this ack, required
    char *memo; // human-readable message for customer, optional
} LWPaymentProtocolACK;

// returns a newly allocated ACK struct that must be freed by calling LWPaymentProtocolACKFree()
LWPaymentProtocolACK *LWPaymentProtocolACKNew(LWPaymentProtocolPayment *payment, const char *memo);

// buf must contain a serialized ACK struct
// returns an ACK struct that must be freed by calling LWPaymentProtocolACKFree()
LWPaymentProtocolACK *LWPaymentProtocolACKParse(const uint8_t *buf, size_t bufLen);

// writes serialized ACK struct to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolACKSerialize(const LWPaymentProtocolACK *ack, uint8_t *buf, size_t bufLen);

// frees memory allocated for ACK struct
void LWPaymentProtocolACKFree(LWPaymentProtocolACK *ack);

typedef struct {
    LWKey senderPubKey; // sender's public key, required
    uint64_t amount; // amount is integer-number-of-satoshis, defaults to 0
    char *pkiType; // none / x509+sha256, default is "none"
    uint8_t *pkiData; // depends on pkiType, optional
    size_t pkiDataLen;
    char *memo; // human-readable description of invoice request for the receiver, optional
    char *notifyUrl; // URL to notify on encrypted payment request ready, optional
    uint8_t *signature; // pki-dependent signature, optional
    size_t sigLen;
} LWPaymentProtocolInvoiceRequest;

// returns a newly allocated invoice request struct that must be freed by calling LWPaymentProtocolInvoiceRequestFree()
LWPaymentProtocolInvoiceRequest *LWPaymentProtocolInvoiceRequestNew(LWKey *senderPubKey, uint64_t amount,
                                                                    const char *pkiType, uint8_t *pkiData,
                                                                    size_t pkiDataLen, const char *memo,
                                                                    const char *notifyUrl, const uint8_t *signature,
                                                                    size_t sigLen);
    
// buf must contain a serialized invoice request
// returns an invoice request struct that must be freed by calling LWPaymentProtocolInvoiceRequestFree()
LWPaymentProtocolInvoiceRequest *LWPaymentProtocolInvoiceRequestParse(const uint8_t *buf, size_t bufLen);
    
// writes serialized invoice request to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolInvoiceRequestSerialize(LWPaymentProtocolInvoiceRequest *req, uint8_t *buf, size_t bufLen);
    
// writes the DER encoded certificate corresponding to index to cert
// returns the number of bytes written to cert, or the total certLen needed if cert is NULL
// returns 0 if index is out-of-bounds
size_t LWPaymentProtocolInvoiceRequestCert(const LWPaymentProtocolInvoiceRequest *req, uint8_t *cert, size_t certLen,
                                           size_t idx);
    
// writes the hash of the request to md needed to sign or verify the request
// returns the number of bytes written, or the total mdLen needed if md is NULL
size_t LWPaymentProtocolInvoiceRequestDigest(LWPaymentProtocolInvoiceRequest *req, uint8_t *md, size_t mdLen);

// frees memory allocated for invoice request struct
void LWPaymentProtocolInvoiceRequestFree(LWPaymentProtocolInvoiceRequest *req);

typedef enum {
    LWPaymentProtocolMessageTypeUnknown = 0,
    LWPaymentProtocolMessageTypeInvoiceRequest = 1,
    LWPaymentProtocolMessageTypeRequest = 2,
    LWPaymentProtocolMessageTypePayment = 3,
    LWPaymentProtocolMessageTypeACK = 4
} LWPaymentProtocolMessageType;

typedef struct {
    LWPaymentProtocolMessageType msgType; // message type of message, required
    uint8_t *message; // serialized payment protocol message, required
    size_t msgLen;
    uint64_t statusCode; // payment protocol status code, optional
    char *statusMsg; // human-readable payment protocol status message, optional
    uint8_t *identifier; // unique key to identify entire exchange, optional (should use sha256 of invoice request)
    size_t identLen;
} LWPaymentProtocolMessage;

// returns a newly allocated message struct that must be freed by calling LWPaymentProtocolMessageFree()
LWPaymentProtocolMessage *LWPaymentProtocolMessageNew(LWPaymentProtocolMessageType msgType, const uint8_t *message,
                                                      size_t msgLen, uint64_t statusCode, const char *statusMsg,
                                                      const uint8_t *identifier, size_t identLen);
    
// buf must contain a serialized message
// returns an message struct that must be freed by calling LWPaymentProtocolMessageFree()
LWPaymentProtocolMessage *LWPaymentProtocolMessageParse(const uint8_t *buf, size_t bufLen);
    
// writes serialized message struct to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolMessageSerialize(const LWPaymentProtocolMessage *msg, uint8_t *buf, size_t bufLen);
    
// frees memory allocated for message struct
void LWPaymentProtocolMessageFree(LWPaymentProtocolMessage *msg);
    
typedef struct {
    LWPaymentProtocolMessageType msgType; // message type of decrypted message, required
    uint8_t *message; // encrypted payment protocol message, required
    size_t msgLen;
    LWKey receiverPubKey; // receiver's public key, required
    LWKey senderPubKey; // sender's public key, required
    uint64_t nonce; // microseconds since epoch, required
    uint8_t *signature; // signature over the full encrypted message with sender/receiver ec key respectively, optional
    size_t sigLen;
    uint8_t *identifier; // unique key to identify entire exchange, optional (should use sha256 of invoice request)
    size_t identLen;
    uint64_t statusCode; // payment protocol status code, optional
    char *statusMsg; // human-readable payment protocol status message, optional
} LWPaymentProtocolEncryptedMessage;

// returns a newly allocated encrypted message struct that must be freed with LWPaymentProtocolEncryptedMessageFree()
// message is the un-encrypted serialized payment protocol message
// one of either receiverKey or senderKey must contain a private key, and the other must contain only a public key
LWPaymentProtocolEncryptedMessage *LWPaymentProtocolEncryptedMessageNew(LWPaymentProtocolMessageType msgType,
                                                                        const uint8_t *message, size_t msgLen,
                                                                        LWKey *receiverKey, LWKey *senderKey,
                                                                        uint64_t nonce,
                                                                        const uint8_t *identifier, size_t identLen,
                                                                        uint64_t statusCode, const char *statusMsg);
    
// buf must contain a serialized encrytped message
// returns an encrypted message struct that must be freed by calling LWPaymentProtocolEncryptedMessageFree()
LWPaymentProtocolEncryptedMessage *LWPaymentProtocolEncryptedMessageParse(const uint8_t *buf, size_t bufLen);
    
// writes serialized encrypted message to buf and returns number of bytes written, or total bufLen needed if buf is NULL
size_t LWPaymentProtocolEncryptedMessageSerialize(LWPaymentProtocolEncryptedMessage *msg, uint8_t *buf, size_t bufLen);

int LWPaymentProtocolEncryptedMessageVerify(LWPaymentProtocolEncryptedMessage *msg, LWKey *pubKey);

size_t LWPaymentProtocolEncryptedMessageDecrypt(LWPaymentProtocolEncryptedMessage *msg, uint8_t *out, size_t outLen,
                                                LWKey *privKey);

// frees memory allocated for encrypted message struct
void LWPaymentProtocolEncryptedMessageFree(LWPaymentProtocolEncryptedMessage *msg);

#ifdef __cplusplus
}
#endif

#endif // BRPaymentProtocol_h
