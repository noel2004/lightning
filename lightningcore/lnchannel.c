
#include "db.h"
#include "log.h"
#include "lnchannel.h"
#include "lnchannel_internal.h"
#include "permute_tx.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "output_to_htlc.h"
#include "pseudorand.h"
#include "remove_dust.h"
#include "secrets.h"
#include "btcnetwork/c/chaintopology.h"
#include "btcnetwork/c/watch.h"
#include "utils/utils.h"
#include "utils/sodium/randombytes.h"
#include <bitcoin/base58.h>
#include <bitcoin/address.h>
#include <bitcoin/script.h>
#include <bitcoin/preimage.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>

struct bitcoin_tx *lnchn_create_close_tx(const tal_t *ctx,
					struct LNchannel *lnchn, u64 fee)
{
	struct channel_state cstate;

	/* We don't need a deep copy here, just fee levels. */
	cstate = *lnchn->local.staging_cstate;
	if (!force_fee(&cstate, fee)) {
		log_unusual(lnchn->log,
			    "lnchn_create_close_tx: can't afford fee %"PRIu64,
			    fee);
		return NULL;
	}

	log_debug(lnchn->log,
		  "creating close-tx with fee %"PRIu64" amounts %u/%u to ",
		  fee,
		  cstate.side[LOCAL].pay_msat / 1000,
		  cstate.side[REMOTE].pay_msat / 1000);
	log_add_struct(lnchn->log, "%s", struct pubkey, &lnchn->local.finalkey);
	log_add_struct(lnchn->log, "/%s", struct pubkey, &lnchn->remote.finalkey);

 	return create_close_tx(ctx,
			       lnchn->closing.our_script,
			       lnchn->closing.their_script,
			       &lnchn->anchor.txid,
			       lnchn->anchor.index,
			       lnchn->anchor.satoshis,
			       cstate.side[LOCAL].pay_msat / 1000,
			       cstate.side[REMOTE].pay_msat / 1000);
}


/* Create a bitcoin close tx, using last signature they sent. */
static const struct bitcoin_tx *mk_bitcoin_close(const tal_t *ctx,
						 struct LNchannel *lnchn)
{
	struct bitcoin_tx *close_tx;
	ecdsa_signature our_close_sig;

	close_tx = lnchn_create_close_tx(ctx, lnchn, lnchn->closing.their_fee);

	lnchn_sign_mutual_close(lnchn, close_tx, &our_close_sig);

	close_tx->input[0].witness
		= bitcoin_witness_2of2(close_tx->input,
				       lnchn->closing.their_sig,
				       &our_close_sig,
				       &lnchn->remote.commitkey,
				       &lnchn->local.commitkey);

	return close_tx;
}


void internal_set_lnchn_state(struct LNchannel *lnchn, enum state newstate,
			   const char *caller, bool db_commit)
{
	log_debug(lnchn->log, "%s: %s => %s", caller,
		  state_name(lnchn->state), state_name(newstate));
	lnchn->state = newstate;
    lnchn->state_height = get_block_height(lnchn->dstate->topology);

	/* We can only route in normal state. */
	if (db_commit)
		db_update_state(lnchn);
}

void internal_lnchn_fail_on_notify(struct LNchannel *lnchn, const char* msg, ...)
{
    va_list ap;

    tal_free(lnchn->notify_fail_reason);
    
    va_start(ap, msg);
    lnchn->notify_fail_reason = tal_vfmt(lnchn, msg, ap);
    va_end(ap);

}

void internal_lnchn_breakdown(struct LNchannel *lnchn)
{

	/* If we have a closing tx, use it. */
	if (lnchn->closing.their_sig) {
		const struct bitcoin_tx *close = mk_bitcoin_close(lnchn, lnchn);
		log_unusual(lnchn->log, "lnchn breakdown: sending close tx");
		broadcast_tx(lnchn->dstate->topology, lnchn, close, NULL);
		tal_free(close);
	/* If we have a signed commit tx (maybe not if we just offered
	 * anchor, or they supplied anchor, or no outputs to us). */
	} else if (lnchn->local.commit && lnchn->local.commit->sig) {
		log_unusual(lnchn->log, "lnchn breakdown: sending commit tx");
		sign_commit_tx(lnchn);
		broadcast_tx(lnchn->dstate->topology, lnchn,
			     lnchn->local.commit->tx, NULL);
	} else {
		log_info(lnchn->log, "lnchn breakdown: nothing to do");
		/* We close immediately. */
		set_lnchn_state(lnchn, STATE_CLOSED, __func__, false);
		db_forget_lnchn(lnchn);
	}

}

/* All unrevoked commit txs must have no HTLCs in them. */
static bool committed_to_htlcs(const struct LNchannel *lnchn)
{
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (htlc_is_dead(h))
			continue;
		return true;
	}
	return false;
}

static void lnchn_calculate_close_fee(struct LNchannel *lnchn)
{
	/* Use actual worst-case length of close tx: based on FIXME-OLD#02's
	 * commitment tx numbers, but only 1 byte for output count */
	const uint64_t txsize = 41 + 221 + 10 + 32 + 32;
	uint64_t maxfee;

	lnchn->closing.our_fee
		= fee_by_feerate(txsize, get_feerate(lnchn->dstate->topology));

	/* FIXME-OLD #2:
	 * The sender MUST set `close_fee` lower than or equal to the
	 * fee of the final commitment transaction, and MUST set
	 * `close_fee` to an even number of satoshis.
	 */
	maxfee = commit_tx_fee(lnchn->local.commit->tx, lnchn->anchor.satoshis);
	if (lnchn->closing.our_fee > maxfee) {
		/* This could only happen if the fee rate dramatically */
		log_unusual(lnchn->log,
			    "Closing fee %"PRIu64" exceeded commit fee %"PRIu64", reducing.",
			    lnchn->closing.our_fee, maxfee);
		lnchn->closing.our_fee = maxfee;

		/* This can happen if actual commit txfee is odd. */
		if (lnchn->closing.our_fee & 1)
			lnchn->closing.our_fee--;
	}
	assert(!(lnchn->closing.our_fee & 1));
}

static void start_closing_in_transaction(struct LNchannel *lnchn)
{
	assert(!committed_to_htlcs(lnchn));

	set_lnchn_state(lnchn, STATE_MUTUAL_CLOSING, __func__, true);

	lnchn_calculate_close_fee(lnchn);
	lnchn->closing.closing_order = lnchn->order_counter++;
	db_update_our_closing(lnchn);
	queue_pkt_close_signature(lnchn);
}

void lnchn_fail(struct LNchannel *lnchn, const char *caller)
{
	/* Don't fail twice. */
	if (state_is_error(lnchn->state) || state_is_onchain(lnchn->state))
		return;

	/* FIXME: Save state here? */
	internal_set_lnchn_state(lnchn, STATE_ERR_BREAKDOWN, caller, false);
	internal_lnchn_breakdown(lnchn);
}

static void lnchn_database_err(struct LNchannel *lnchn)
{
	lnchn_fail(lnchn, __func__);

}


/* This is the io loop while we're negotiating closing tx. */
static bool closing_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	const CloseSignature *c = pkt->close_signature;
	struct bitcoin_tx *close_tx;
	ecdsa_signature theirsig;

	assert(lnchn->state == STATE_MUTUAL_CLOSING);

	if (pkt->pkt_case != PKT__PKT_CLOSE_SIGNATURE)
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

	log_info(lnchn->log, "closing_pkt_in: they offered close fee %"PRIu64,
		 c->close_fee);

	/* FIXME-OLD #2:
	 *
	 * The sender MUST set `close_fee` lower than or equal to the fee of the
	 * final commitment transaction, and MUST set `close_fee` to an even
	 * number of satoshis.
	 */
	if ((c->close_fee & 1)
	    || c->close_fee > commit_tx_fee(lnchn->remote.commit->tx,
					    lnchn->anchor.satoshis)) {
		return lnchn_comms_err(lnchn, pkt_err(lnchn, "Invalid close fee"));
	}

	/* FIXME: Don't accept tiny fee at all? */

	/* FIXME-OLD #2:
	   ... otherwise it SHOULD propose a
	   value strictly between the received `close_fee` and its
	   previously-sent `close_fee`.
	*/
	if (lnchn->closing.their_sig) {
		/* We want more, they should give more. */
		if (lnchn->closing.our_fee > lnchn->closing.their_fee) {
			if (c->close_fee <= lnchn->closing.their_fee)
				return lnchn_comms_err(lnchn,
						      pkt_err(lnchn, "Didn't increase close fee"));
		} else {
			if (c->close_fee >= lnchn->closing.their_fee)
				return lnchn_comms_err(lnchn,
						      pkt_err(lnchn, "Didn't decrease close fee"));
		}
	}

	/* FIXME-OLD #2:
	 *
	 * The receiver MUST check `sig` is valid for the close
	 * transaction with the given `close_fee`, and MUST fail the
	 * connection if it is not. */
	if (!proto_to_signature(c->sig, &theirsig))
		return lnchn_comms_err(lnchn,
				      pkt_err(lnchn, "Invalid signature format"));

	close_tx = lnchn_create_close_tx(c, lnchn, c->close_fee);
	if (!check_tx_sig(close_tx, 0,
			  NULL,
			  lnchn->anchor.witnessscript,
			  &lnchn->remote.commitkey, &theirsig))
		return lnchn_comms_err(lnchn,
				      pkt_err(lnchn, "Invalid signature"));

	tal_free(lnchn->closing.their_sig);
	lnchn->closing.their_sig = tal_dup(lnchn,
					  ecdsa_signature, &theirsig);
	lnchn->closing.their_fee = c->close_fee;
	lnchn->closing.sigs_in++;

	if (!db_update_their_closing(lnchn))
		return lnchn_database_err(lnchn);

	if (lnchn->closing.our_fee != lnchn->closing.their_fee) {
		/* FIXME-OLD #2:
		 *
		 * If the receiver agrees with the fee, it SHOULD reply with a
		 * `close_signature` with the same `close_fee` value,
		 * otherwise it SHOULD propose a value strictly between the
		 * received `close_fee` and its previously-sent `close_fee`.
		 */

		/* Adjust our fee to close on their fee. */
		u64 sum;

		/* Beware overflow! */
		sum = (u64)lnchn->closing.our_fee + lnchn->closing.their_fee;

		lnchn->closing.our_fee = sum / 2;
		if (lnchn->closing.our_fee & 1)
			lnchn->closing.our_fee++;

		log_info(lnchn->log, "accept_pkt_close_sig: we change to %"PRIu64,
			 lnchn->closing.our_fee);

		lnchn->closing.closing_order = lnchn->order_counter++;

		db_start_transaction(lnchn);
		db_update_our_closing(lnchn);
		if (db_commit_transaction(lnchn) != NULL)
			return lnchn_database_err(lnchn);

		queue_pkt_close_signature(lnchn);
	}

	/* Note corner case: we may *now* agree with them! */
	if (lnchn->closing.our_fee == lnchn->closing.their_fee) {
		const struct bitcoin_tx *close;
		log_info(lnchn->log, "accept_pkt_close_sig: we agree");
		/* FIXME-OLD #2:
		 *
		 * Once a node has sent or received a `close_signature` with
		 * matching `close_fee` it SHOULD close the connection and
		 * SHOULD sign and broadcast the final closing transaction.
		 */
		close = mk_bitcoin_close(lnchn, lnchn);
		broadcast_tx(lnchn->dstate->topology, lnchn, close, NULL);
		tal_free(close);
		return false;
	}

	return true;
}

/* We can get update_commit in both normal and shutdown states. */
static Pkt *handle_pkt_commit(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err;
	const char *errmsg;
	struct sha256 preimage;
	struct commit_info *ci;
	bool to_them_only;
	/* FIXME: We can actually merge these two... */
	static const struct htlcs_table commit_changes[] = {
		{ RCVD_ADD_REVOCATION, RCVD_ADD_ACK_COMMIT },
		{ RCVD_REMOVE_HTLC, RCVD_REMOVE_COMMIT },
		{ RCVD_ADD_HTLC, RCVD_ADD_COMMIT },
		{ RCVD_REMOVE_REVOCATION, RCVD_REMOVE_ACK_COMMIT }
	};
	static const struct feechanges_table commit_feechanges[] = {
		{ RCVD_FEECHANGE_REVOCATION, RCVD_FEECHANGE_ACK_COMMIT },
		{ RCVD_FEECHANGE, RCVD_FEECHANGE_COMMIT }
	};
	static const struct htlcs_table revocation_changes[] = {
		{ RCVD_ADD_ACK_COMMIT, SENT_ADD_ACK_REVOCATION },
		{ RCVD_REMOVE_COMMIT, SENT_REMOVE_REVOCATION },
		{ RCVD_ADD_COMMIT, SENT_ADD_REVOCATION },
		{ RCVD_REMOVE_ACK_COMMIT, SENT_REMOVE_ACK_REVOCATION }
	};
	static const struct feechanges_table revocation_feechanges[] = {
		{ RCVD_FEECHANGE_ACK_COMMIT, SENT_FEECHANGE_ACK_REVOCATION },
		{ RCVD_FEECHANGE_COMMIT, SENT_FEECHANGE_REVOCATION }
	};

	ci = internal_new_commit_info(lnchn, lnchn->local.commit->commit_num + 1);

	db_start_transaction(lnchn);

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	errmsg = changestates(lnchn,
			      commit_changes, ARRAY_SIZE(commit_changes),
			      commit_feechanges, ARRAY_SIZE(commit_feechanges),
			      true);
	if (errmsg) {
		db_abort_transaction(lnchn);
		return pkt_err(lnchn, "%s", errmsg);
	}

	/* Create new commit info for this commit tx. */
	ci->revocation_hash = lnchn->local.next_revocation_hash;

	/* FIXME-OLD #2:
	 *
	 * A receiving node MUST apply all local acked and unacked
	 * changes except unacked fee changes to the local commitment
	 */
	/* (We already applied them to staging_cstate as we went) */
	ci->cstate = copy_cstate(ci, lnchn->local.staging_cstate);
	ci->tx = create_commit_tx(ci, lnchn, &ci->revocation_hash,
				  ci->cstate, LOCAL, &to_them_only);
	bitcoin_txid(ci->tx, &ci->txid);

	log_debug(lnchn->log, "Check tx %"PRIu64" sig", ci->commit_num);
	log_add_struct(lnchn->log, " for %s", struct channel_state, ci->cstate);
	log_add_struct(lnchn->log, " (txid %s)", struct sha256_double, &ci->txid);

	/* FIXME-OLD #2:
	 *
	 * If the commitment transaction has only a single output which pays
	 * to the other node, `sig` MUST be unset.  Otherwise, a sending node
	 * MUST apply all remote acked and unacked changes except unacked fee
	 * changes to the remote commitment before generating `sig`.
	 */
	if (!to_them_only)
		ci->sig = tal(ci, ecdsa_signature);

	err = accept_pkt_commit(lnchn, pkt, ci->sig);
	if (err)
		return err;

	/* FIXME-OLD #2:
	 *
	 * A receiving node MUST apply all local acked and unacked changes
	 * except unacked fee changes to the local commitment, then it MUST
	 * check `sig` is valid for that transaction.
	 */
	if (ci->sig && !check_tx_sig(ci->tx, 0,
				     NULL,
				     lnchn->anchor.witnessscript,
				     &lnchn->remote.commitkey,
				     ci->sig)) {
		db_abort_transaction(lnchn);
		return pkt_err(lnchn, "Bad signature");
	}

	/* Switch to the new commitment. */
	tal_free(lnchn->local.commit);
	lnchn->local.commit = ci;
	lnchn->local.commit->order = lnchn->order_counter++;

	db_new_commit_info(lnchn, LOCAL, NULL);
	lnchn_get_revocation_hash(lnchn, ci->commit_num + 1,
				 &lnchn->local.next_revocation_hash);
	lnchn->their_commitsigs++;

	/* Now, send the revocation. */

	/* We have their signature on the current one, right? */
	assert(to_them_only || lnchn->local.commit->sig);
	assert(lnchn->local.commit->commit_num > 0);

	errmsg = changestates(lnchn,
			      revocation_changes, ARRAY_SIZE(revocation_changes),
			      revocation_feechanges,
			      ARRAY_SIZE(revocation_feechanges),
			      true);
	if (errmsg) {
		log_broken(lnchn->log, "queue_pkt_revocation: %s", errmsg);
		db_abort_transaction(lnchn);
		return pkt_err(lnchn, "Database error");
	}

	lnchn_get_revocation_preimage(lnchn, lnchn->local.commit->commit_num - 1,
				     &preimage);

	/* Fire off timer if this ack caused new changes */
	if (lnchn_uncommitted_changes(lnchn))
		remote_changes_pending(lnchn);

	queue_pkt_revocation(lnchn, &preimage, &lnchn->local.next_revocation_hash);

	/* If we're shutting down and no more HTLCs, begin closing */
	if (lnchn->closing.their_script && !committed_to_htlcs(lnchn))
		start_closing_in_transaction(lnchn);

	if (db_commit_transaction(lnchn) != NULL)
		return pkt_err(lnchn, "Database error");

	return NULL;
}

static Pkt *handle_pkt_htlc_add(struct LNchannel *lnchn, const Pkt *pkt)
{
	struct htlc *htlc;
	Pkt *err;

	err = accept_pkt_htlc_add(lnchn, pkt, &htlc);
	if (err)
		return err;
	assert(htlc->state == RCVD_ADD_HTLC);

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT offer `amount_msat` it cannot pay for in
	 * the remote commitment transaction at the current `fee_rate` (see
	 * "Fee Calculation" ).  A node SHOULD fail the connection if
	 * this occurs.
	 */
	if (!cstate_add_htlc(lnchn->local.staging_cstate, htlc, true)) {
		u64 id = htlc->id;
		log_broken_struct(lnchn->log, "They cannot afford htlc %s",
				  struct htlc, htlc);
		log_add_struct(lnchn->log, " cstate %s",
			       struct channel_state,
			       lnchn->local.staging_cstate);
		tal_free(htlc);
		return pkt_err(lnchn, "Cannot afford htlc %"PRIu64, id);
	}
	return NULL;
}

static Pkt *handle_pkt_htlc_fail(struct LNchannel *lnchn, const Pkt *pkt)
{
	struct htlc *htlc;
	u8 *fail;
	Pkt *err;

	err = accept_pkt_htlc_fail(lnchn, pkt, &htlc, &fail);
	if (err)
		return err;

	/* This can happen with re-transmissions; simply note it. */
	if (htlc->fail) {
		log_debug(lnchn->log, "HTLC %"PRIu64" failed twice", htlc->id);
		htlc->fail = tal_free(htlc->fail);
	}

	db_start_transaction(lnchn);

	set_htlc_fail(lnchn, htlc, fail, tal_count(fail));
	tal_free(fail);

	if (db_commit_transaction(lnchn) != NULL)
		return pkt_err(lnchn, "database error");

	cstate_fail_htlc(lnchn->local.staging_cstate, htlc);

	/* FIXME-OLD #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	htlc_changestate(htlc, SENT_ADD_ACK_REVOCATION, RCVD_REMOVE_HTLC, false);
	return NULL;
}

static Pkt *handle_pkt_htlc_fulfill(struct LNchannel *lnchn, const Pkt *pkt)
{
	struct htlc *htlc;
	Pkt *err;
	struct preimage r;

	err = accept_pkt_htlc_fulfill(lnchn, pkt, &htlc, &r);
	if (err)
		return err;

	/* Reconnect may mean HTLC was already fulfilled.  That's OK. */
	if (!htlc->r) {
		db_start_transaction(lnchn);
		set_htlc_rval(lnchn, htlc, &r);

		/* We can relay this upstream immediately. */
		our_htlc_fulfilled(lnchn, htlc);
		if (db_commit_transaction(lnchn) != NULL)
			return pkt_err(lnchn, "database error");
	}

	/* FIXME-OLD #2:
	 *
	 * ... and the receiving node MUST add the HTLC fulfill/fail
	 * to the unacked changeset for its local commitment.
	 */
	cstate_fulfill_htlc(lnchn->local.staging_cstate, htlc);
	htlc_changestate(htlc, SENT_ADD_ACK_REVOCATION, RCVD_REMOVE_HTLC, false);
	return NULL;
}

//static void set_feechange(struct LNchannel *lnchn, u64 fee_rate,
//			  enum feechange_state state)
//{
//	/* If we already have a feechange for this commit, simply update it. */
//	if (lnchn->feechanges[state]) {
//		log_debug(lnchn->log, "Feechange: fee %"PRIu64" to %"PRIu64,
//			  lnchn->feechanges[state]->fee_rate,
//			  fee_rate);
//		lnchn->feechanges[state]->fee_rate = fee_rate;
//	} else {
//		log_debug(lnchn->log, "Feechange: New fee %"PRIu64, fee_rate);
//		lnchn->feechanges[state] = new_feechange(lnchn, fee_rate, state);
//	}
//}
//
//static Pkt *handle_pkt_feechange(struct LNchannel *lnchn, const Pkt *pkt)
//{
//	u64 feerate;
//	Pkt *err;
//
//	err = accept_pkt_update_fee(lnchn, pkt, &feerate);
//	if (err)
//		return err;
//
//	/* FIXME-OLD #2:
//	 *
//	 * The sending node MUST NOT send a `fee_rate` which it could not
//	 * afford (see "Fee Calculation), were it applied to the receiving
//	 * node's commitment transaction.  The receiving node SHOULD fail the
//	 * connection if this occurs.
//	 */
//	if (!can_afford_feerate(lnchn->local.staging_cstate, feerate, REMOTE))
//		return pkt_err(lnchn, "Cannot afford feerate %"PRIu64,
//			       feerate);
//
//	set_feechange(lnchn, feerate, RCVD_FEECHANGE);
//	return NULL;
//}

static Pkt *handle_pkt_revocation(struct LNchannel *lnchn, const Pkt *pkt,
				  enum state next_state)
{
	Pkt *err;
	const char *errmsg;
	static const struct htlcs_table changes[] = {
		{ SENT_ADD_COMMIT, RCVD_ADD_REVOCATION },
		{ SENT_REMOVE_ACK_COMMIT, RCVD_REMOVE_ACK_REVOCATION },
		{ SENT_ADD_ACK_COMMIT, RCVD_ADD_ACK_REVOCATION },
		{ SENT_REMOVE_COMMIT, RCVD_REMOVE_REVOCATION }
	};
	static const struct feechanges_table feechanges[] = {
		{ SENT_FEECHANGE_COMMIT, RCVD_FEECHANGE_REVOCATION },
		{ SENT_FEECHANGE_ACK_COMMIT, RCVD_FEECHANGE_ACK_REVOCATION }
	};

	err = accept_pkt_revocation(lnchn, pkt);
	if (err)
		return err;

	/* FIXME-OLD #2:
	 *
	 * The receiver of `update_revocation`... MUST add the remote
	 * unacked changes to the set of local acked changes.
	 */
	db_start_transaction(lnchn);
	errmsg = changestates(lnchn, changes, ARRAY_SIZE(changes),
			      feechanges, ARRAY_SIZE(feechanges), true);
	if (errmsg) {
		log_broken(lnchn->log, "accept_pkt_revocation: %s", errmsg);
		db_abort_transaction(lnchn);
		return pkt_err(lnchn, "failure accepting update_revocation: %s",
			       errmsg);
	}
	db_save_shachain(lnchn);
	db_update_next_revocation_hash(lnchn);
	set_lnchn_state(lnchn, next_state, __func__, true);
	db_remove_their_prev_revocation_hash(lnchn);

	/* If we're shutting down and no more HTLCs, begin closing */
	if (lnchn->closing.their_script && !committed_to_htlcs(lnchn))
		start_closing_in_transaction(lnchn);

	if (db_commit_transaction(lnchn) != NULL)
		return pkt_err(lnchn, "database error");

	return NULL;
}

/* This is the io loop while we're doing shutdown. */
static bool shutdown_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(lnchn->state == STATE_SHUTDOWN
	       || lnchn->state == STATE_SHUTDOWN_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_REVOCATION:
		if (lnchn->state == STATE_SHUTDOWN)
			return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);
		else {
			err = handle_pkt_revocation(lnchn, pkt, STATE_SHUTDOWN);
			if (!err)
				lnchn_update_complete(lnchn);
		}
		break;

	case PKT__PKT_UPDATE_ADD_HTLC:
		/* FIXME-OLD #2:
		 *
		 * A node MUST NOT send a `update_add_htlc` after a
		 * `close_shutdown` */
		if (lnchn->closing.their_script)
			err = pkt_err(lnchn, "Update during shutdown");
		else
			err = handle_pkt_htlc_add(lnchn, pkt);
		break;

	case PKT__PKT_CLOSE_SHUTDOWN:
		/* FIXME-OLD #2:
		 *
		 * A node... MUST NOT send more than one `close_shutdown`. */
		if (lnchn->closing.their_script)
			return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);
		else {
			err = accept_pkt_close_shutdown(lnchn, pkt);
			if (!err) {
				db_start_transaction(lnchn);
				db_set_their_closing_script(lnchn);
				/* If no more HTLCs, we're closing. */
				if (!committed_to_htlcs(lnchn))
					start_closing_in_transaction(lnchn);
				if (db_commit_transaction(lnchn) != NULL)
					err = pkt_err(lnchn, "database error");
			}
		}
		break;

	case PKT__PKT_UPDATE_FULFILL_HTLC:
		err = handle_pkt_htlc_fulfill(lnchn, pkt);
		break;
	case PKT__PKT_UPDATE_FAIL_HTLC:
		err = handle_pkt_htlc_fail(lnchn, pkt);
		break;
	case PKT__PKT_UPDATE_FEE:
		err = handle_pkt_feechange(lnchn, pkt);
		break;
	case PKT__PKT_UPDATE_COMMIT:
		err = handle_pkt_commit(lnchn, pkt);
		break;
	case PKT__PKT_ERROR:
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

	case PKT__PKT_AUTH:
	case PKT__PKT_OPEN:
	case PKT__PKT_OPEN_ANCHOR:
	case PKT__PKT_OPEN_COMMIT_SIG:
	case PKT__PKT_OPEN_COMPLETE:
	case PKT__PKT_CLOSE_SIGNATURE:
	default:
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);
	}

	if (err)
		return lnchn_comms_err(lnchn, err);

	return true;
}

static bool lnchn_start_shutdown(struct LNchannel *lnchn)
{
	enum state newstate;
	//u8 *redeemscript;

	/* We might have uncommited changes; if so, commit them now. */
	if (!do_commit(lnchn, NULL))
		return false;

	db_start_transaction(lnchn);

	db_begin_shutdown(lnchn);

	/* If they started close, we might not have sent ours. */
	assert(!lnchn->closing.our_script);

	//redeemscript = bitcoin_redeem_single(lnchn, &lnchn->local.finalkey);

    lnchn->closing.our_script = lnchn->final_redeemscript;//scriptpubkey_p2sh(lnchn, redeemscript);
	//tal_free(redeemscript);

	/* FIXME-OLD #2:
	 *
	 * A node SHOULD send a `close_shutdown` (if it has
	 * not already) after receiving `close_shutdown`.
	 */
	lnchn->closing.shutdown_order = lnchn->order_counter++;
	db_set_our_closing_script(lnchn);

	queue_pkt_close_shutdown(lnchn);

	if (lnchn->state == STATE_NORMAL_COMMITTING) {
		newstate = STATE_SHUTDOWN_COMMITTING;
	} else {
		newstate = STATE_SHUTDOWN;
	}
	set_lnchn_state(lnchn, newstate, __func__, true);

	/* Catch case where we've exchanged and had no HTLCs anyway. */
	if (lnchn->closing.their_script && !committed_to_htlcs(lnchn))
		start_closing_in_transaction(lnchn);

	return db_commit_transaction(lnchn) == NULL;
}


static bool command_htlc_set_fail(struct LNchannel *lnchn, struct htlc *htlc,
				  enum fail_error error_code, const char *why)
{
	const u8 *fail = failinfo_create(htlc,
					 &lnchn->dstate->id, error_code, why);

	set_htlc_fail(lnchn, htlc, fail, tal_count(fail));
	tal_free(fail);
	return command_htlc_fail(lnchn, htlc);
}

static bool command_htlc_fail(struct LNchannel *lnchn, struct htlc *htlc)
{
	/* If onchain, nothing we can do. */
	if (!state_can_remove_htlc(lnchn->state))
		return false;

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	cstate_fail_htlc(lnchn->remote.staging_cstate, htlc);

	htlc_changestate(htlc, RCVD_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC, false);

	remote_changes_pending(lnchn);

	queue_pkt_htlc_fail(lnchn, htlc);
	return true;
}

static bool command_htlc_fulfill(struct LNchannel *lnchn, struct htlc *htlc)
{
	if (lnchn->state == STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL
	    || lnchn->state == STATE_CLOSE_ONCHAIN_OUR_UNILATERAL) {
		return fulfill_onchain(lnchn, htlc);
	}

	if (!state_can_remove_htlc(lnchn->state))
		return false;

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST add the HTLC fulfill/fail to the
	 * unacked changeset for its remote commitment
	 */
	cstate_fulfill_htlc(lnchn->remote.staging_cstate, htlc);

	htlc_changestate(htlc, RCVD_ADD_ACK_REVOCATION, SENT_REMOVE_HTLC, false);

	remote_changes_pending(lnchn);

	queue_pkt_htlc_fulfill(lnchn, htlc);
	return true;
}

const char *command_htlc_add(struct LNchannel *lnchn, u64 msatoshi,
			     unsigned int expiry,
			     const struct sha256 *rhash,
			     struct htlc *src,
			     const u8 *route,
			     u32 *error_code,
			     struct htlc **htlc)
{
	struct abs_locktime locktime;

	if (!blocks_to_abs_locktime(expiry, &locktime)) {
		log_unusual(lnchn->log, "add_htlc: fail: bad expiry %u", expiry);
		*error_code = BAD_REQUEST_400;
		return "bad expiry";
	}

	if (expiry < get_block_height(lnchn->dstate->topology) + lnchn->dstate->config.min_htlc_expiry) {
		log_unusual(lnchn->log, "add_htlc: fail: expiry %u is too soon",
			    expiry);
		*error_code = BAD_REQUEST_400;
		return "expiry too soon";
	}

	if (expiry > get_block_height(lnchn->dstate->topology) + lnchn->dstate->config.max_htlc_expiry) {
		log_unusual(lnchn->log, "add_htlc: fail: expiry %u is too far",
			    expiry);
		*error_code = BAD_REQUEST_400;
		return "expiry too far";
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT add a HTLC if it would result in it
	 * offering more than 300 HTLCs in the remote commitment transaction.
	 */
	if (lnchn->remote.staging_cstate->side[LOCAL].num_htlcs == 300) {
		log_unusual(lnchn->log, "add_htlc: fail: already at limit");
		*error_code = SERVICE_UNAVAILABLE_503;
		return "channel full";
	}

	if (!state_can_add_htlc(lnchn->state)) {
		log_unusual(lnchn->log, "add_htlc: fail: lnchn state %s",
			    state_name(lnchn->state));
		*error_code = NOT_FOUND_404;
		return "lnchn not available";
	}

	*htlc = lnchn_new_htlc(lnchn, msatoshi, rhash, expiry, SENT_ADD_HTLC);

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST add the HTLC addition to the unacked
	 * changeset for its remote commitment
	 */
	if (!cstate_add_htlc(lnchn->remote.staging_cstate, *htlc, true)) {
		/* FIXME-OLD #2:
		 *
		 * A node MUST NOT offer `amount_msat` it cannot pay for in
		 * the remote commitment transaction at the current `fee_rate`
		 */
 		log_unusual(lnchn->log, "add_htlc: fail: Cannot afford %"PRIu64
 			    " milli-satoshis in their commit tx",
 			    msatoshi);
		log_add_struct(lnchn->log, " channel state %s",
			       struct channel_state,
			       lnchn->remote.staging_cstate);
 		*htlc = tal_free(*htlc);
		*error_code = SERVICE_UNAVAILABLE_503;
		return "cannot afford htlc";
 	}

	remote_changes_pending(lnchn);

	queue_pkt_htlc_add(lnchn, *htlc);

	/* Make sure we never offer the same one twice. */
	lnchn->htlc_id_counter++;

	return NULL;
}

/* FIXME-OLD #2:
 *
 * On disconnection, a node MUST reverse any uncommitted changes sent by the
 * other side (ie. `update_add_htlc`, `update_fee`, `update_fail_htlc` and
 * `update_fulfill_htlc` for which no `update_commit` has been received).  A
 * node SHOULD retain the `r` value from the `update_fulfill_htlc`, however.
*/
static void forget_uncommitted_changes(struct LNchannel *lnchn)
{
	struct htlc *h;
	struct htlc_map_iter it;
	bool retry;

	if (!lnchn->remote.commit || !lnchn->remote.commit->cstate)
		return;

	log_debug(lnchn->log, "Forgetting uncommitted");
	log_debug_struct(lnchn->log, "LOCAL: changing from %s",
			 struct channel_state, lnchn->local.staging_cstate);
	log_add_struct(lnchn->log, " to %s",
			 struct channel_state, lnchn->local.commit->cstate);
	log_debug_struct(lnchn->log, "REMOTE: changing from %s",
			 struct channel_state, lnchn->remote.staging_cstate);
	log_add_struct(lnchn->log, " to %s",
			 struct channel_state, lnchn->remote.commit->cstate);

	tal_free(lnchn->local.staging_cstate);
	tal_free(lnchn->remote.staging_cstate);
	lnchn->local.staging_cstate
		= copy_cstate(lnchn, lnchn->local.commit->cstate);
	lnchn->remote.staging_cstate
		= copy_cstate(lnchn, lnchn->remote.commit->cstate);

	/* We forget everything we're routing, and re-send.  This
	 * works for the reload-from-database case as well as the
	 * normal reconnect. */
again:
	retry = false;
	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		switch (h->state) {
		case SENT_ADD_HTLC:
			/* Adjust counter to lowest HTLC removed */
			if (lnchn->htlc_id_counter > h->id) {
				log_debug(lnchn->log,
					  "Lowering htlc_id_counter to %"PRIu64,
					  h->id);
				lnchn->htlc_id_counter = h->id;
			}
			 /* Fall thru */
		case RCVD_ADD_HTLC:
			log_debug(lnchn->log, "Forgetting %s %"PRIu64,
				  htlc_state_name(h->state), h->id);
			/* May miss some due to delete reorg. */
			tal_free(h);
			retry = true;
			break;
		case RCVD_REMOVE_HTLC:
			log_debug(lnchn->log, "Undoing %s %"PRIu64,
				  htlc_state_name(h->state), h->id);
			htlc_undostate(h, RCVD_REMOVE_HTLC,
				       SENT_ADD_ACK_REVOCATION);
			break;
		case SENT_REMOVE_HTLC:
			log_debug(lnchn->log, "Undoing %s %"PRIu64,
				  htlc_state_name(h->state), h->id);
			htlc_undostate(h, SENT_REMOVE_HTLC,
				       RCVD_ADD_ACK_REVOCATION);
			break;
		default:
			break;
		}
	}
	if (retry)
		goto again;

	/* Forget uncommitted feechanges */
	lnchn->feechanges[SENT_FEECHANGE]
		= tal_free(lnchn->feechanges[SENT_FEECHANGE]);
	lnchn->feechanges[RCVD_FEECHANGE]
		= tal_free(lnchn->feechanges[RCVD_FEECHANGE]);

	/* Make sure our HTLC counter is correct. */
	if (lnchn->htlc_id_counter != 0)
		assert(htlc_get(&lnchn->htlcs, lnchn->htlc_id_counter-1, LOCAL));
	assert(!htlc_get(&lnchn->htlcs, lnchn->htlc_id_counter, LOCAL));
}


static bool want_feechange(const struct LNchannel *lnchn)
{
	if (!state_is_normal(lnchn->state) && !state_is_shutdown(lnchn->state))
		return false;
	log_debug(lnchn->log, "Current fee_rate: %"PRIu64" want %"PRIu64,
		  lnchn->local.staging_cstate->fee_rate,
		  desired_commit_feerate(lnchn->dstate));
	/* FIXME: Send fee changes when we want it */
	return false;
}

static void destroy_lnchn(struct LNchannel *lnchn)
{
	if (lnchn->conn)
		io_close(lnchn->conn);
	list_del_from(&lnchn->dstate->lnchns, &lnchn->list);
}


struct commit_info *internal_new_commit_info(const tal_t *ctx, u64 commit_num)
{
	struct commit_info *ci = tal(ctx, struct commit_info);
	ci->commit_num = commit_num;
	ci->tx = NULL;
	ci->cstate = NULL;
	ci->sig = NULL;
	ci->order = (s64)-1LL;
	return ci;
}



struct LNchannel *new_LNChannel(struct lightningd_state *dstate,
		      struct log *log)
{
	struct LNchannel *lnchn = tal(dstate, struct LNchannel);

	lnchn->state = STATE_INIT;
    lnchn->state_height = 0;
	lnchn->id = NULL;
	lnchn->dstate = dstate;
	lnchn->secrets = NULL;
	lnchn->anchor.ok_depth = -1;
//	lnchn->order_counter = 0;
	lnchn->their_commitsigs = 0;
	lnchn->closing.their_sig = NULL;
	lnchn->closing.our_script = NULL;
	lnchn->closing.their_script = NULL;
	lnchn->closing.shutdown_order = (s64)-1LL;
	lnchn->closing.closing_order = (s64)-1LL;
	lnchn->closing.sigs_in = 0;
	lnchn->onchain.tx = NULL;
	lnchn->onchain.resolved = NULL;
	lnchn->onchain.htlcs = NULL;
	lnchn->commit_timer = NULL;
	lnchn->their_prev_revocation_hash = NULL;
	lnchn->fake_close = false;
	lnchn->output_enabled = true;
    lnchn->local.offer_anchor = false;
	lnchn->broadcast_index = 0;
	if (!blocks_to_rel_locktime(dstate->config.locktime_blocks,
				    &lnchn->local.locktime))
		fatal("Could not convert locktime_blocks");
	lnchn->local.mindepth = dstate->config.anchor_confirms;
	lnchn->local.commit = lnchn->remote.commit = NULL;
	lnchn->local.staging_cstate = lnchn->remote.staging_cstate = NULL;
	lnchn->log = tal_steal(lnchn, log);
	log_debug(lnchn->log, "New lnchn %p", lnchn);
    lnchn->notify_fail_reason = NULL;

    lnchn->remote.offer_anchor = false;

	htlc_map_init(&lnchn->htlcs);
//	memset(lnchn->feechanges, 0, sizeof(lnchn->feechanges));
	shachain_init(&lnchn->their_preimages);

    /* init runtime */
    lnchn->rt.outsourcing_counter = 0;
    lnchn->rt.outsourcing_lock = false;
    lnchn->rt.outsourcing_f = NULL;
    lnchn->rt.commit_msg_cache = NULL;
    lnchn->rt.their_last_commit_txid = NULL;

	tal_add_destructor(lnchn, destroy_lnchn);
	return lnchn;
}

//static void htlc_destroy(struct htlc *htlc)
//{
//	if (!htlc_map_del(&htlc->lnchn->htlcs, htlc))
//		fatal("Could not find htlc to destroy");
//}

struct htlc *internal_new_htlc(struct LNchannel *lnchn,
			   u64 msatoshi,
			   const struct sha256 *rhash,
			   u32 expiry, u32 routing,
			   enum htlc_state state)
{
	struct htlc *h = tal(lnchn, struct htlc);
	h->state = state;
	h->msatoshi = msatoshi;
	h->rhash = *rhash;
    h->routing = routing;
	h->r = NULL;
	h->fail = NULL;
	if (!blocks_to_abs_locktime(expiry, &h->expiry))
		fatal("Invalid HTLC expiry %u", expiry);

    h->src_expiry = NULL;
	if (htlc_owner(h) == LOCAL) {
		/* If we're paying, give it a little longer. will be adjust later if
           we are in chain
        */
	    h->deadline = expiry
				+ lnchn->dstate->config.min_htlc_expiry;
    }
    else
        h->deadline = 0;

    h->history[0] = lnchn->local.commit ? lnchn->local.commit->commit_num : 0;
    h->history[1] = h->history[0] + 1;

	//htlc_map_add(&lnchn->htlcs, h);
	//tal_add_destructor(h, htlc_destroy);
    h->in_commit_output[0] = h->in_commit_output[1] 
        = h->in_commit_output[2] = -1;

	return h;
}

/* 
    rebuild all data related with other channel (currently only src expiry in htlcs)
    and make some verification
*/
void reopen_LNChannel(struct LNchannel *lnchn)
{
    struct htlc_map_iter it;
    struct htlc *h, *srchtlc;
    enum feechange_state i;

    //verify signature from remote
    if (lnchn->remote.commit && lnchn->remote.commit->sig &&
        !check_tx_sig(lnchn->remote.commit->tx, 0,
        NULL,
        lnchn->anchor.witnessscript,
        &lnchn->remote.commitkey,
        lnchn->remote.commit->sig)) {

        log_broken(lnchn->log, "reopen check signature fail");
        lnchn_fail(lnchn, __func__);
        return;
    }

    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        if (!htlc_is_fixed(h))continue;

        /* rebuild deadline and src_expiry*/
        if (htlc_route_has_source(h)) {
            srchtlc = lite_query_htlc_direct(lnchn->dstate->channels, &h->rhash, false);
            if (!srchtlc){
                //TODO: should mark it as something special?
                continue;
            }

            h->src_expiry = tal(h, struct abs_locktime);
            *h->src_expiry = srchtlc->expiry;
	        h->deadline = abs_locktime_to_blocks(h->src_expiry)
				    - lnchn->dstate->config.deadline_blocks;

            lite_release_htlc(lnchn->dstate->channels, srchtlc);
        }
        else if (htlc_route_is_end(h)) {

            if (!h->r) {
                //TODO: notify invoice again
            }            
        }

    }

}

void internal_htlc_update_deadline(struct LNchannel *lnchn, struct htlc *h)
{
    struct htlc * srchtlc = lite_query_htlc_direct(lnchn->dstate->channels, 
        &h->rhash, false);
    if (!srchtlc) {
        log_broken(lnchn->log, "can't get source of htlc [%s]",
            tal_hexstr(h, &h->rhash, sizeof(h->rhash)));
        return;
    }

    h->src_expiry = tal(h, struct abs_locktime);
    *h->src_expiry = srchtlc->expiry;
    h->deadline = abs_locktime_to_blocks(h->src_expiry)
        - lnchn->dstate->config.deadline_blocks;

    lite_release_htlc(lnchn->dstate->channels, srchtlc);
}


//
///* Have any of our HTLCs passed their deadline? */
//static bool any_deadline_past(struct LNchannel *lnchn)
//{
//	u32 height = get_block_height(lnchn->dstate->topology);
//	struct htlc_map_iter it;
//	struct htlc *h;
//
//	for (h = htlc_map_first(&lnchn->htlcs, &it);
//	     h;
//	     h = htlc_map_next(&lnchn->htlcs, &it)) {
//		if (htlc_is_dead(h))
//			continue;
//		if (htlc_owner(h) != LOCAL)
//			continue;
//		if (height >= h->deadline) {
//			log_unusual_struct(lnchn->log,
//					   "HTLC %s deadline has passed",
//					   struct htlc, h);
//			return true;
//		}
//	}
//	return false;
//}
//
//static void check_htlc_expiry(struct LNchannel *lnchn)
//{
//	u32 height = get_block_height(lnchn->dstate->topology);
//	struct htlc_map_iter it;
//	struct htlc *h;
//
//	/* Check their currently still-existing htlcs for expiry */
//	for (h = htlc_map_first(&lnchn->htlcs, &it);
//	     h;
//	     h = htlc_map_next(&lnchn->htlcs, &it)) {
//		assert(!abs_locktime_is_seconds(&h->expiry));
//
//		/* Only their consider HTLCs which are completely locked in. */
//		if (h->state != RCVD_ADD_ACK_REVOCATION)
//			continue;
//
//		/* We give it an extra block, to avoid the worst of the
//		 * inter-node timing issues. */
//		if (height <= abs_locktime_to_blocks(&h->expiry))
//			continue;
//
//		db_start_transaction(lnchn);
//		/* This can fail only if we're in an error state. */
//		command_htlc_set_fail(lnchn, h,
//				      REQUEST_TIMEOUT_408, "timed out");
//		if (db_commit_transaction(lnchn) != NULL) {
//			lnchn_fail(lnchn, __func__);
//			return;
//		}
//	}
//
//	/* FIXME-OLD #2:
//	 *
//	 * A node MUST NOT offer a HTLC after this deadline, and MUST
//	 * fail the connection if an HTLC which it offered is in
//	 * either node's current commitment transaction past this
//	 * deadline.
//	 */
//
//	/* To save logic elsewhere (ie. to avoid signing a new commit with a
//	 * past-deadline HTLC) we also check staged HTLCs.
//	 */
//	if (!state_is_normal(lnchn->state))
//		return;
//
//	if (any_deadline_past(lnchn))
//		lnchn_fail(lnchn, __func__);
//}

//void notify_new_block(struct chain_topology *topo, unsigned int height)
//{
//	struct lightningd_state *dstate = tal_parent(topo);
//	/* This is where we check for anchor timeouts. */
//	struct LNchannel *lnchn;
//
//	list_for_each(&dstate->lnchns, lnchn, list) {
//		if (!state_is_waiting_for_anchor(lnchn->state))
//			continue;
//
//		/* If we haven't seen anchor yet, we can timeout. */
//		if (height >= lnchn->anchor.min_depth
//		    + dstate->config.anchor_onchain_wait
//		    + dstate->config.anchor_confirms) {
//			queue_pkt_err(lnchn, pkt_err(lnchn, "Funding timeout"));
//			set_lnchn_state(lnchn, STATE_ERR_ANCHOR_TIMEOUT, __func__,
//				       false);
//			lnchn_breakdown(lnchn);
//		}
//	}
//}




///* Return earliest block we're interested in, or 0 for none. */
//u32 get_lnchn_min_block(struct lightningd_state *dstate)
//{
//	u32 min_block = 0;
//	struct LNchannel *lnchn;
//
//	/* If loaded from database, go back to earliest possible lnchn anchor. */
//	list_for_each(&dstate->lnchns, lnchn, list) {
//		if (!lnchn->anchor.min_depth)
//			continue;
//		if (min_block == 0 || lnchn->anchor.min_depth < min_block)
//			min_block = lnchn->anchor.min_depth;
//	}
//	return min_block;
//}



/* To avoid freeing underneath ourselves, we free outside event loop. */
void cleanup_lnchns(struct lightningd_state *dstate)
{
	struct LNchannel *lnchn, *next;

	list_for_each_safe(&dstate->lnchns, lnchn, next, list) {
		/* Deletes itself from list. */
		if (!lnchn->conn && lnchn->state == STATE_CLOSED)
			tal_free(lnchn);
	}
}





//static void json_close(struct command *cmd,
//		       const char *buffer, const jsmntok_t *params)
//{
//	struct LNchannel *lnchn;
//	jsmntok_t *lnchnidtok;
//
//	if (!json_get_params(buffer, params,
//			     "lnchnid", &lnchnidtok,
//			     NULL)) {
//		command_fail(cmd, "Need lnchnid");
//		return;
//	}
//
//	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
//	if (!lnchn) {
//		command_fail(cmd, "Could not find lnchn with that lnchnid");
//		return;
//	}
//
//	if (!state_is_normal(lnchn->state) && !state_is_opening(lnchn->state)) {
//		command_fail(cmd, "lnchn is already closing: state %s",
//			     state_name(lnchn->state));
//		return;
//	}
//
//	if (!lnchn_start_shutdown(lnchn)) {
//		command_fail(cmd, "Database error");
//		return;
//	}
//	/* FIXME: Block until closed! */
//	command_success(cmd, null_response(cmd));
//}


//static void json_feerate(struct command *cmd,
//			 const char *buffer, const jsmntok_t *params)
//{
//	jsmntok_t *feeratetok;
//	u64 feerate;
//
//	if (!json_get_params(buffer, params,
//			     "feerate", &feeratetok,
//			     NULL)) {
//		command_fail(cmd, "Need feerate");
//		return;
//	}
//
//	if (!json_tok_u64(buffer, feeratetok, &feerate)) {
//		command_fail(cmd, "Invalid feerate");
//		return;
//	}
//	log_debug(cmd->jcon->log, "Fee rate changed to %"PRIu64, feerate);
//	cmd->dstate->topology->default_fee_rate = feerate;
//
//	command_success(cmd, null_response(cmd));
//}








