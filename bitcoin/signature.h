#ifndef LIGHTNING_BITCOIN_SIGNATURE_H
#define LIGHTNING_BITCOIN_SIGNATURE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>
#include <stddef.h>

struct sha256_double;
struct bitcoin_tx;
struct pubkey;
struct privkey;
struct bitcoin_tx_output;

enum sighash_type {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80
};

typedef struct ecdsa_signature_ {
    unsigned char data[64];
} ecdsa_signature;

void sign_hash(const struct privkey *p,
	       const struct sha256_double *h,
           ecdsa_signature *s);

bool check_signed_hash(const struct sha256_double *hash,
		       const ecdsa_signature *signature,
		       const struct pubkey *key);

/* All tx input scripts must be set to 0 len. */
void sign_tx_input(struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript,
		   const u8 *witness,
		   const struct privkey *privkey, const struct pubkey *pubkey,
    ecdsa_signature *sig);

/* Does this sig sign the tx with this input for this pubkey. */
bool check_tx_sig(struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript,
		  const u8 *witness,
		  const struct pubkey *key,
		  const ecdsa_signature *sig);

/* Signature must have low S value. */
bool sig_valid(const ecdsa_signature *sig);

/* Give DER encoding of signature: returns length used (<= 72). */
size_t signature_to_der(u8 der[72], const ecdsa_signature *s);

/* Parse DER encoding into signature sig */
bool signature_from_der(const u8 *der, size_t len, ecdsa_signature *sig);

#endif /* LIGHTNING_BITCOIN_SIGNATURE_H */
