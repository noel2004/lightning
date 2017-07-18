#ifndef LIGHTNING_DAEMON_SECRETS_H
#define LIGHTNING_DAEMON_SECRETS_H
/* Routines to handle private keys. */
#include "config.h"
#include <bitcoin/signature.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct LNchannel;
struct lightningd_state;
struct sha256;

//void privkey_sign(struct lightningd_state *dstate, const void *src, size_t len,
//		  ecdsa_signature *sig);

void lnchn_sign_theircommit(const struct LNchannel *lnchn,
			   struct bitcoin_tx *commit,
			   ecdsa_signature *sig);

void lnchn_sign_ourcommit(const struct LNchannel *lnchn,
			 struct bitcoin_tx *commit,
			 ecdsa_signature *sig);

void lnchn_sign_spend(const struct LNchannel *lnchn,
		     struct bitcoin_tx *spend,
		     const u8 *commit_witnessscript,
		     ecdsa_signature *sig);


void lnchn_sign_htlc(const struct LNchannel *lnchn,
			    struct bitcoin_tx *spend,
			    const u8 *htlc_witnessscript,
			    ecdsa_signature *sig);

void lnchn_sign_mutual_close(const struct LNchannel *lnchn,
			    struct bitcoin_tx *close,
			    ecdsa_signature *sig);

void lnchn_sign_steal_input(const struct LNchannel *lnchn,
			   struct bitcoin_tx *spend,
			   size_t i,
			   const u8 *witnessscript,
			   ecdsa_signature *sig);

const char *lnchn_secrets_for_db(const tal_t *ctx, struct LNchannel *lnchn);

void lnchn_set_secrets_from_db(struct LNchannel *lnchn,
			      const void *commit_privkey,
			      size_t commit_privkey_len,
			      const void *final_privkey,
			      size_t final_privkey_len,
			      const void *revocation_seed,
			      size_t revocation_seed_len);

void lnchn_secrets_init(struct LNchannel *lnchn);

void lnchn_get_revocation_hash(const struct LNchannel *lnchn, u64 index,
			      struct sha256 *rhash);
void lnchn_get_revocation_preimage(const struct LNchannel *lnchn, u64 index,
				  struct sha256 *preimage);

//void secrets_init(struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_SECRETS_H */
