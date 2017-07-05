#ifndef LIGHTNING_BITCOIN_PUBKEY_H
#define LIGHTNING_BITCOIN_PUBKEY_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct privkey;
struct bitcoin_address;

#define PUBKEY_DER_LEN 33

struct pubkey {
    bool compressed;
	/* Unpacked pubkey (as used by libsecp256k1 internally) */
    union {
        unsigned char data[33];
        unsigned char data_uc[65];
    } pubkey;
    unsigned int sign_type;
};

/* Convert from hex string of DER (scriptPubKey from validateaddress) */
bool pubkey_from_hexstr(const char *derstr, size_t derlen, struct pubkey *key);

/* Convert from hex string of DER (scriptPubKey from validateaddress) */
char *pubkey_to_hexstr(const tal_t *ctx, const struct pubkey *key);

/* Pubkey from privkey */
bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key);

///* Pubkey from DER encoding. */
//bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key);
//
///* Pubkey to DER encoding: must be valid pubkey. */
//void pubkey_to_der(u8 der[PUBKEY_DER_LEN], const struct pubkey *key);

/* Are these keys equal? */
bool pubkey_eq(const struct pubkey *a, const struct pubkey *b);

/* Compare the keys `a` and `b`. Return <0 if `a`<`b`, 0 if equal and >0 otherwise */
int pubkey_cmp(const struct pubkey *a, const struct pubkey *b);

/**
 * pubkey_to_hash160 - Get the hash for p2pkh payments for a given pubkey
 */
void pubkey_to_hash160(const struct pubkey *pk, struct bitcoin_address *hash);
#endif /* LIGHTNING_PUBKEY_H */
