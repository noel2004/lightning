
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

    log_debug(lnchn->log, "Channel fail on a message: %s", lnchn->notify_fail_reason);
}

void internal_lnchn_temp_breakdown(struct LNchannel *lnchn, const char* reason)
{
    size_t len = strlen(reason);
    assert(!lnchn->rt.temp_errormsg);

    lnchn->rt.temp_errormsg = tal_arrz(lnchn, u8, len + 1);
    memcpy(lnchn->rt.temp_errormsg, reason, len);

    internal_set_lnchn_state(lnchn, STATE_ERR_TEMP, __func__, false);
}

void internal_lnchn_breakdown(struct LNchannel *lnchn)
{

	///* If we have a closing tx, use it. */
	//if (lnchn->closing.their_sig) {
	//	const struct bitcoin_tx *close = mk_bitcoin_close(lnchn, lnchn);
	//	log_unusual(lnchn->log, "lnchn breakdown: sending close tx");
	//	broadcast_tx(lnchn->dstate->topology, lnchn, close, NULL);
	//	tal_free(close);
	///* If we have a signed commit tx (maybe not if we just offered
	// * anchor, or they supplied anchor, or no outputs to us). */
	//} else if (lnchn->local.commit && lnchn->local.commit->sig) {
	//	log_unusual(lnchn->log, "lnchn breakdown: sending commit tx");
	//	sign_commit_tx(lnchn);
	//	broadcast_tx(lnchn->dstate->topology, lnchn,
	//		     lnchn->local.commit->tx, NULL);
	//} else {
	//	log_info(lnchn->log, "lnchn breakdown: nothing to do");
	//	/* We close immediately. */
	//	set_lnchn_state(lnchn, STATE_CLOSED, __func__, false);
	//	db_forget_lnchn(lnchn);
	//}

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

//static void start_closing_in_transaction(struct LNchannel *lnchn)
//{
//	assert(!committed_to_htlcs(lnchn));
//
//	set_lnchn_state(lnchn, STATE_MUTUAL_CLOSING, __func__, true);
//
//	lnchn_calculate_close_fee(lnchn);
//	lnchn->closing.closing_order = lnchn->order_counter++;
//	db_update_our_closing(lnchn);
//	queue_pkt_close_signature(lnchn);
//}

void lnchn_fail(struct LNchannel *lnchn, const char *caller)
{
	/* Don't fail twice. */
	if (state_is_error(lnchn->state) || state_is_onchain(lnchn->state))
		return;

	/* FIXME: Save state here? */
	internal_set_lnchn_state(lnchn, STATE_ERR_BREAKDOWN, caller, false);
	internal_lnchn_breakdown(lnchn);
}



//
///* This is the io loop while we're negotiating closing tx. */
//static bool closing_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
//{
//	const CloseSignature *c = pkt->close_signature;
//	struct bitcoin_tx *close_tx;
//	ecdsa_signature theirsig;
//
//	assert(lnchn->state == STATE_MUTUAL_CLOSING);
//
//	if (pkt->pkt_case != PKT__PKT_CLOSE_SIGNATURE)
//		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);
//
//	log_info(lnchn->log, "closing_pkt_in: they offered close fee %"PRIu64,
//		 c->close_fee);
//
//	/* FIXME-OLD #2:
//	 *
//	 * The sender MUST set `close_fee` lower than or equal to the fee of the
//	 * final commitment transaction, and MUST set `close_fee` to an even
//	 * number of satoshis.
//	 */
//	if ((c->close_fee & 1)
//	    || c->close_fee > commit_tx_fee(lnchn->remote.commit->tx,
//					    lnchn->anchor.satoshis)) {
//		return lnchn_comms_err(lnchn, pkt_err(lnchn, "Invalid close fee"));
//	}
//
//	/* FIXME: Don't accept tiny fee at all? */
//
//	/* FIXME-OLD #2:
//	   ... otherwise it SHOULD propose a
//	   value strictly between the received `close_fee` and its
//	   previously-sent `close_fee`.
//	*/
//	if (lnchn->closing.their_sig) {
//		/* We want more, they should give more. */
//		if (lnchn->closing.our_fee > lnchn->closing.their_fee) {
//			if (c->close_fee <= lnchn->closing.their_fee)
//				return lnchn_comms_err(lnchn,
//						      pkt_err(lnchn, "Didn't increase close fee"));
//		} else {
//			if (c->close_fee >= lnchn->closing.their_fee)
//				return lnchn_comms_err(lnchn,
//						      pkt_err(lnchn, "Didn't decrease close fee"));
//		}
//	}
//
//	/* FIXME-OLD #2:
//	 *
//	 * The receiver MUST check `sig` is valid for the close
//	 * transaction with the given `close_fee`, and MUST fail the
//	 * connection if it is not. */
//	if (!proto_to_signature(c->sig, &theirsig))
//		return lnchn_comms_err(lnchn,
//				      pkt_err(lnchn, "Invalid signature format"));
//
//	close_tx = lnchn_create_close_tx(c, lnchn, c->close_fee);
//	if (!check_tx_sig(close_tx, 0,
//			  NULL,
//			  lnchn->anchor.witnessscript,
//			  &lnchn->remote.commitkey, &theirsig))
//		return lnchn_comms_err(lnchn,
//				      pkt_err(lnchn, "Invalid signature"));
//
//	tal_free(lnchn->closing.their_sig);
//	lnchn->closing.their_sig = tal_dup(lnchn,
//					  ecdsa_signature, &theirsig);
//	lnchn->closing.their_fee = c->close_fee;
//	lnchn->closing.sigs_in++;
//
//	if (!db_update_their_closing(lnchn))
//		return lnchn_database_err(lnchn);
//
//	if (lnchn->closing.our_fee != lnchn->closing.their_fee) {
//		/* FIXME-OLD #2:
//		 *
//		 * If the receiver agrees with the fee, it SHOULD reply with a
//		 * `close_signature` with the same `close_fee` value,
//		 * otherwise it SHOULD propose a value strictly between the
//		 * received `close_fee` and its previously-sent `close_fee`.
//		 */
//
//		/* Adjust our fee to close on their fee. */
//		u64 sum;
//
//		/* Beware overflow! */
//		sum = (u64)lnchn->closing.our_fee + lnchn->closing.their_fee;
//
//		lnchn->closing.our_fee = sum / 2;
//		if (lnchn->closing.our_fee & 1)
//			lnchn->closing.our_fee++;
//
//		log_info(lnchn->log, "accept_pkt_close_sig: we change to %"PRIu64,
//			 lnchn->closing.our_fee);
//
//		lnchn->closing.closing_order = lnchn->order_counter++;
//
//		db_start_transaction(lnchn);
//		db_update_our_closing(lnchn);
//		if (db_commit_transaction(lnchn) != NULL)
//			return lnchn_database_err(lnchn);
//
//		queue_pkt_close_signature(lnchn);
//	}
//
//	/* Note corner case: we may *now* agree with them! */
//	if (lnchn->closing.our_fee == lnchn->closing.their_fee) {
//		const struct bitcoin_tx *close;
//		log_info(lnchn->log, "accept_pkt_close_sig: we agree");
//		/* FIXME-OLD #2:
//		 *
//		 * Once a node has sent or received a `close_signature` with
//		 * matching `close_fee` it SHOULD close the connection and
//		 * SHOULD sign and broadcast the final closing transaction.
//		 */
//		close = mk_bitcoin_close(lnchn, lnchn);
//		broadcast_tx(lnchn->dstate->topology, lnchn, close, NULL);
//		tal_free(close);
//		return false;
//	}
//
//	return true;
//}



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

//    lnchn->closing.our_script = lnchn->final_redeemscript;//scriptpubkey_p2sh(lnchn, redeemscript);
	//tal_free(redeemscript);

	/* FIXME-OLD #2:
	 *
	 * A node SHOULD send a `close_shutdown` (if it has
	 * not already) after receiving `close_shutdown`.
	 */

	db_set_our_closing_script(lnchn);

	queue_pkt_close_shutdown(lnchn);

	if (lnchn->state == STATE_NORMAL_COMMITTING) {
		newstate = STATE_SHUTDOWN_COMMITTING;
	} else {
		newstate = STATE_SHUTDOWN;
	}
	internal_set_lnchn_state(lnchn, newstate, __func__, true);

	/* Catch case where we've exchanged and had no HTLCs anyway. */
	if (lnchn->closing.their_script && !committed_to_htlcs(lnchn))
		start_closing_in_transaction(lnchn);

	return db_commit_transaction(lnchn) == NULL;
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
    lnchn->rt.prev_call = NULL;
    lnchn->rt.changed_htlc_cache = NULL;
    lnchn->rt.their_last_commit = NULL;
    lnchn->rt.temp_errormsg = NULL;
    memset(lnchn->rt.feechanges, 0, sizeof(lnchn->rt.feechanges));

//	tal_add_destructor(lnchn, destroy_lnchn);
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

    h->in_commit_output[0] = h->in_commit_output[1]
        = h->in_commit_output[2] = -1;

    //htlc_map_add(&lnchn->htlcs, h);
    //tal_add_destructor(h, htlc_destroy);

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
    /* enum feechange_state i; */

    //verify signature from remote
    if (lnchn->remote.commit && lnchn->remote.commit->sig &&
        !check_tx_sig(lnchn->remote.commit->tx, 0,
        NULL,
        lnchn->anchor.witnessscript,
        &lnchn->remote.commitkey,
        lnchn->remote.commit->sig))
    {

        log_broken(lnchn->log, "reopen check signature fail");
        lnchn_fail(lnchn, __func__);
        return;
    }

    //update htlc's state
    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        if (!htlc_route_is_chain(h))continue;

        internal_htlc_update(lnchn, h);

    }
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








