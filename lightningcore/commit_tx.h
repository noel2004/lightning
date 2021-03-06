#ifndef LIGHTNING_COMMIT_TX_H
#define LIGHTNING_COMMIT_TX_H
#include "config.h"
#include "htlc.h"
#include <ccan/tal/tal.h>

struct channel_state;
struct sha256;
struct pubkey;
struct LNchannel;
struct bition_tx;

u32 commit_generator_version();
bool check_commit_generator_compatible(u32 ver);

u8 *wscript_for_htlc(const tal_t *ctx,
		     const struct LNchannel *lnchn,
		     const struct htlc *h,
		     const struct sha256 *rhash,
		     enum side side);

/* Returns scriptpubkey: *wscript is NULL if it's a direct p2wpkh. */
u8 *commit_output_to_us(const tal_t *ctx,
			const struct LNchannel *peer,
			const struct sha256 *rhash,
			enum side side,
			u8 **wscript);

/* Returns scriptpubkey: *wscript is NULL if it's a direct p2wpkh. */
u8 *commit_output_to_them(const tal_t *ctx,
			  const struct LNchannel *lnchn,
			  const struct sha256 *rhash,
			  enum side side,
			  u8 **wscript);

/* Create commitment tx to spend the anchor tx output; doesn't fill in
 * input scriptsig.
   htlc_updates include two NULL (or one) to indicate the redeem output
 */
struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    struct LNchannel *lnchn,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum side side,
				    bool *otherside_only,
                    struct htlc ***htlc_updates);

void   update_htlc_in_channel(struct LNchannel *lnchn, 
    enum side side,
    struct htlc **htlc_updates);

size_t find_redeem_output_from_commit_tx(const struct bitcoin_tx* commit_tx,
    u8* script);

size_t find_htlc_output_from_commit_tx(const struct bitcoin_tx* commit_tx,
    u8* wscript);

#endif
