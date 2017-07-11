#ifndef LIGHTNING_DAEMON_DB_H
#define LIGHTNING_DAEMON_DB_H
#include "config.h"
#include "lnchannel.h"
#include <stdbool.h>

void db_init(struct lightningd_state *dstate);

void db_start_transaction(struct LNchannel *lnchn);
void db_abort_transaction(struct LNchannel *lnchn);
const char *db_commit_transaction(struct LNchannel *lnchn);

void db_add_wallet_privkey(struct lightningd_state *dstate,
			   const struct privkey *privkey);

bool db_add_lnchn_address(struct lightningd_state *dstate,
			 const struct LNchannel_address *addr);

/* Must NOT be inside transaction. */
bool db_update_their_closing(struct LNchannel *lnchn);
bool db_new_pay_command(struct lightningd_state *dstate,
			const struct sha256 *rhash,
			const struct pubkey *ids,
			u64 msatoshi,
			const struct htlc *htlc);
bool db_replace_pay_command(struct lightningd_state *dstate,
			    const struct sha256 *rhash,
			    const struct pubkey *ids,
			    u64 msatoshi,
			    const struct htlc *htlc);
bool db_new_invoice(struct lightningd_state *dstate,
		    u64 msatoshi,
		    const char *label,
		    const struct preimage *r);

bool db_remove_invoice(struct lightningd_state *dstate,
		       const char *label);

/* FIXME: save error handling until db_commit_transaction for calls
 * which have to be inside transaction anyway. */

/* Must be inside transaction. */
void db_create_lnchn(struct LNchannel *lnchn);
void db_set_visible_state(struct LNchannel *lnchn);
void db_set_anchor(struct LNchannel *lnchn);
void db_new_htlc(struct LNchannel *lnchn, const struct htlc *htlc);
void db_new_feechange(struct LNchannel *lnchn, const struct feechange *feechange);
void db_htlc_fulfilled(struct LNchannel *lnchn, const struct htlc *htlc);
void db_htlc_failed(struct LNchannel *lnchn, const struct htlc *htlc);
void db_update_htlc_state(struct LNchannel *lnchn, const struct htlc *htlc,
				 enum htlc_state oldstate);
void db_complete_pay_command(struct lightningd_state *dstate,
			     const struct htlc *htlc);
void db_resolve_invoice(struct lightningd_state *dstate,
			const char *label, u64 paid_num);
void db_update_feechange_state(struct LNchannel *lnchn,
			       const struct feechange *f,
			       enum feechange_state oldstate);
void db_remove_feechange(struct LNchannel *lnchn, const struct feechange *feechange,
			 enum feechange_state oldstate);
void db_new_commit_info(struct LNchannel *lnchn, enum side side,
			const struct sha256 *prev_rhash);
void db_remove_their_prev_revocation_hash(struct LNchannel *lnchn);
void db_update_next_revocation_hash(struct LNchannel *lnchn);
void db_save_shachain(struct LNchannel *lnchn);
void db_update_state(struct LNchannel *lnchn);
void db_begin_shutdown(struct LNchannel *lnchn);
void db_set_our_closing_script(struct LNchannel *lnchn);
void db_update_our_closing(struct LNchannel *lnchn);
void db_set_their_closing_script(struct LNchannel *lnchn);

void db_add_commit_map(struct LNchannel *lnchn,
		       const struct sha256_double *txid, u64 commit_num);

void db_forget_lnchn(struct LNchannel *lnchn);
#endif /* LIGHTNING_DAEMON_DB_H */
