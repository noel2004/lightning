
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

static bool command_htlc_set_fail(struct LNchannel *lnchn, struct htlc *htlc,
				  enum fail_error error_code, const char *why);
static bool command_htlc_fail(struct LNchannel *lnchn, struct htlc *htlc);
static bool command_htlc_fulfill(struct LNchannel *lnchn, struct htlc *htlc);
static void try_commit(struct LNchannel *lnchn);

void lnchn_add_their_commit(struct LNchannel *lnchn,
			   const struct sha256_double *txid, u64 commit_num)
{
	struct their_commit *tc = tal(lnchn, struct their_commit);
	tc->txid = *txid;
	tc->commit_num = commit_num;

	db_add_commit_map(lnchn, txid, commit_num);
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

/* Sign and local commit tx */
static void sign_commit_tx(struct LNchannel *lnchn)
{
	ecdsa_signature sig;

	/* Can't be signed already, and can't have scriptsig! */
	assert(!lnchn->local.commit->tx->input[0].script);
	assert(!lnchn->local.commit->tx->input[0].witness);

	lnchn_sign_ourcommit(lnchn, lnchn->local.commit->tx, &sig);

	lnchn->local.commit->tx->input[0].witness
		= bitcoin_witness_2of2(lnchn->local.commit->tx->input,
				       lnchn->local.commit->sig,
				       &sig,
				       &lnchn->remote.commitkey,
				       &lnchn->local.commitkey);
}

static u64 commit_tx_fee(const struct bitcoin_tx *commit, u64 anchor_satoshis)
{
	uint64_t i, total = 0;

	for (i = 0; i < tal_count(commit->output); i++)
		total += commit->output[i].amount;

	assert(anchor_satoshis >= total);
	return anchor_satoshis - total;
}

static bool lnchn_uncommitted_changes(const struct LNchannel *lnchn)
{
	struct htlc_map_iter it;
	struct htlc *h;
	enum feechange_state i;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (htlc_has(h, HTLC_REMOTE_F_PENDING))
			return true;
	}
	/* Pending feechange we sent, or pending ack of theirs. */
	for (i = 0; i < ARRAY_SIZE(lnchn->feechanges); i++) {
		if (!lnchn->feechanges[i])
			continue;
		if (feechange_state_flags(i) & HTLC_REMOTE_F_PENDING)
			return true;
	}
	return false;
}

static void remote_changes_pending(struct LNchannel *lnchn)
{
	if (!lnchn->commit_timer) {
		log_debug(lnchn->log, "remote_changes_pending: adding timer");
		lnchn->commit_timer = new_reltimer(&lnchn->dstate->timers, lnchn,
						  lnchn->dstate->config.commit_time,
						  try_commit, lnchn);
	} else
		log_debug(lnchn->log, "remote_changes_pending: timer already exists");
}

static void lnchn_update_complete(struct LNchannel *lnchn)
{
	log_debug(lnchn->log, "lnchn_update_complete");

	/* Have we got more changes in the meantime? */
	if (lnchn_uncommitted_changes(lnchn)) {
		log_debug(lnchn->log, "lnchn_update_complete: more changes!");
		remote_changes_pending(lnchn);
	}
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

void internal_lnchn_breakdown(struct LNchannel *lnchn)
{
	if (lnchn->commit_jsoncmd) {
		command_fail(lnchn->commit_jsoncmd, "lnchn breakdown");
		lnchn->commit_jsoncmd = NULL;
	}

	/* FIXME: Reason. */
	if (lnchn->open_jsoncmd)  {
		command_fail(lnchn->open_jsoncmd, "lnchn breakdown");
		lnchn->open_jsoncmd = NULL;
	}

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

	/* Always wake lnchn to close or flush packets. */
	io_wake(lnchn);
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

static struct io_plan *lnchn_close(struct io_conn *conn, struct LNchannel *lnchn)
{
	/* Tell writer to wrap it up (may have to xmit first) */
	io_wake(lnchn);
	/* We do nothing more. */
	return io_wait(conn, NULL, io_never, NULL);
}

void lnchn_fail(struct LNchannel *lnchn, const char *caller)
{
	/* Don't fail twice. */
	if (state_is_error(lnchn->state) || state_is_onchain(lnchn->state))
		return;

	/* FIXME: Save state here? */
	set_lnchn_state(lnchn, STATE_ERR_BREAKDOWN, caller, false);
	internal_lnchn_breakdown(lnchn);
}

/* Communication failed: send err (if non-NULL), then dump to chain and close. */
static bool lnchn_comms_err(struct LNchannel *lnchn, Pkt *err)
{
	if (err)
		queue_pkt_err(lnchn, err);

	lnchn_fail(lnchn, __func__);
	return false;
}

static bool lnchn_database_err(struct LNchannel *lnchn)
{
	return lnchn_comms_err(lnchn, pkt_err(lnchn, "database error"));
}





static void funding_tx_failed(struct LNchannel *lnchn,
			      int exitstatus,
			      const char *err)
{
	const char *str = tal_fmt(lnchn, "Broadcasting funding gave %i: %s",
				  exitstatus, err);

	lnchn_open_complete(lnchn, str);
	lnchn_breakdown(lnchn);
	queue_pkt_err(lnchn, pkt_err(lnchn, "Funding failed"));
}

static bool open_ouranchor_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err;

	if (pkt->pkt_case != PKT__PKT_OPEN_COMMIT_SIG)
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

	lnchn->local.commit->sig = tal(lnchn->local.commit,
				      ecdsa_signature);
	err = accept_pkt_open_commit_sig(lnchn, pkt,
					 lnchn->local.commit->sig);
	if (!err &&
	    !check_tx_sig(lnchn->local.commit->tx, 0,
			  NULL,
			  lnchn->anchor.witnessscript,
			  &lnchn->remote.commitkey,
			  lnchn->local.commit->sig))
		err = pkt_err(lnchn, "Bad signature");

	if (err) {
		lnchn->local.commit->sig = tal_free(lnchn->local.commit->sig);
		return lnchn_comms_err(lnchn, err);
	}

	lnchn->their_commitsigs++;

	db_start_transaction(lnchn);
	db_set_anchor(lnchn);
	db_new_commit_info(lnchn, LOCAL, NULL);
	set_lnchn_state(lnchn,
		       STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE,
		       __func__, true);
	if (db_commit_transaction(lnchn) != NULL)
		return lnchn_database_err(lnchn);

	broadcast_tx(lnchn->dstate->topology,
		     lnchn, lnchn->anchor.tx, funding_tx_failed);
	lnchn_watch_anchor(lnchn, lnchn->local.mindepth);
	return true;
}


static bool open_theiranchor_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err;
	const char *db_err;

	if (pkt->pkt_case != PKT__PKT_OPEN_ANCHOR)
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

	err = accept_pkt_anchor(lnchn, pkt);
	if (err) {
		lnchn_open_complete(lnchn, err->error->problem);
		return lnchn_comms_err(lnchn, err);
	}

	lnchn->anchor.ours = false;
	if (!setup_first_commit(lnchn)) {
		err = pkt_err(lnchn, "Insufficient funds for fee");
		lnchn_open_complete(lnchn, err->error->problem);
		return lnchn_comms_err(lnchn, err);
	}

	log_debug_struct(lnchn->log, "Creating sig for %s",
			 struct bitcoin_tx,
			 lnchn->remote.commit->tx);
	log_add_struct(lnchn->log, " using key %s",
		       struct pubkey, &lnchn->local.commitkey);

	lnchn->remote.commit->sig = tal(lnchn->remote.commit,
				       ecdsa_signature);
	lnchn_sign_theircommit(lnchn, lnchn->remote.commit->tx,
			      lnchn->remote.commit->sig);

	lnchn->remote.commit->order = lnchn->order_counter++;
	db_start_transaction(lnchn);
	db_set_anchor(lnchn);
	db_new_commit_info(lnchn, REMOTE, NULL);
	lnchn_add_their_commit(lnchn,
			      &lnchn->remote.commit->txid,
			      lnchn->remote.commit->commit_num);
	set_lnchn_state(lnchn, STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE,
		       __func__, true);
	db_err = db_commit_transaction(lnchn);
	if (db_err) {
		lnchn_open_complete(lnchn, db_err);
		return lnchn_database_err(lnchn);
	}

	queue_pkt_open_commit_sig(lnchn);
	lnchn_watch_anchor(lnchn, lnchn->local.mindepth);
	return true;
}

static bool open_wait_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err;
	const char *db_err;

	/* If they want to shutdown during this, we do mutual close dance. */
	if (pkt->pkt_case == PKT__PKT_CLOSE_SHUTDOWN) {
		err = accept_pkt_close_shutdown(lnchn, pkt);
		if (err)
			return lnchn_comms_err(lnchn, err);

		lnchn_open_complete(lnchn, "Shutdown request received");
		db_start_transaction(lnchn);
		db_set_their_closing_script(lnchn);
		start_closing_in_transaction(lnchn);
		if (db_commit_transaction(lnchn) != NULL)
			return lnchn_database_err(lnchn);

		return false;
	}

	switch (lnchn->state) {
	case STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE:
	case STATE_OPEN_WAIT_THEIRCOMPLETE:
		if (pkt->pkt_case != PKT__PKT_OPEN_COMPLETE)
			return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

		err = accept_pkt_open_complete(lnchn, pkt);
		if (err) {
			lnchn_open_complete(lnchn, err->error->problem);
			return lnchn_comms_err(lnchn, err);
		}

		db_start_transaction(lnchn);
		if (lnchn->state == STATE_OPEN_WAIT_THEIRCOMPLETE) {
			lnchn_open_complete(lnchn, NULL);
			set_lnchn_state(lnchn, STATE_NORMAL, __func__, true);
			announce_channel(lnchn->dstate, lnchn);
			sync_routing_table(lnchn->dstate, lnchn);
		} else {
			set_lnchn_state(lnchn, STATE_OPEN_WAIT_ANCHORDEPTH,
				       __func__, true);
		}

		db_err = db_commit_transaction(lnchn);
		if (db_err) {
			lnchn_open_complete(lnchn, db_err);
			return lnchn_database_err(lnchn);
		}
		return true;

	case STATE_OPEN_WAIT_ANCHORDEPTH:
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

	default:
		log_unusual(lnchn->log,
			    "%s: unexpected state %s",
			    __func__, state_name(lnchn->state));
		lnchn_fail(lnchn, __func__);
		return false;
	}
}

static void set_htlc_rval(struct LNchannel *lnchn,
			  struct htlc *htlc, const struct preimage *rval)
{
	assert(!htlc->r);
	assert(!htlc->fail);
	htlc->r = tal_dup(htlc, struct preimage, rval);
	db_htlc_fulfilled(lnchn, htlc);
}

static void set_htlc_fail(struct LNchannel *lnchn,
			  struct htlc *htlc, const void *fail, size_t len)
{
	assert(!htlc->r);
	assert(!htlc->fail);
	htlc->fail = tal_dup_arr(htlc, u8, fail, len, 0);
	db_htlc_failed(lnchn, htlc);
}

static void route_htlc_onwards(struct LNchannel *lnchn,
			       struct htlc *htlc,
			       u64 msatoshi,
			       const u8 *pb_id,
			       const u8 *rest_of_route,
			       const struct LNchannel *only_dest)
{
	struct LNchannel *next;
	struct htlc *newhtlc;
	enum fail_error error_code;
	const char *err;

	if (!only_dest) {
		log_debug_struct(lnchn->log, "Forwarding HTLC %s",
				 struct sha256, &htlc->rhash);
		log_add(lnchn->log, " (id %"PRIu64")", htlc->id);
	}

	next = find_lnchn_by_pkhash(lnchn->dstate, pb_id);
	if (!next || !next->nc) {
		log_unusual(lnchn->log, "Can't route HTLC %"PRIu64": no %slnchn ",
			    htlc->id, next ? "ready " : "");
		if (!lnchn->dstate->dev_never_routefail)
			command_htlc_set_fail(lnchn, htlc, NOT_FOUND_404,
					      "Unknown lnchn");
		return;
	}

	if (only_dest && next != only_dest)
		return;

	/* Offered fee must be sufficient. */
	if ((s64)(htlc->msatoshi - msatoshi)
	    < connection_fee(next->nc, msatoshi)) {
		log_unusual(lnchn->log,
			    "Insufficient fee for HTLC %"PRIu64
			    ": %"PRIi64" on %"PRIu64,
			    htlc->id, htlc->msatoshi - msatoshi,
			    msatoshi);
		command_htlc_set_fail(lnchn, htlc, PAYMENT_REQUIRED_402,
				      "Insufficent fee");
		return;
	}

	log_debug_struct(lnchn->log, "HTLC forward to %s",
			 struct pubkey, next->id);

	/* This checks the HTLC itself is possible. */
	err = command_htlc_add(next, msatoshi,
			       abs_locktime_to_blocks(&htlc->expiry)
			       - next->nc->delay,
			       &htlc->rhash, htlc, rest_of_route,
			       &error_code, &newhtlc);
	if (err)
		command_htlc_set_fail(lnchn, htlc, error_code, err);
}

static void their_htlc_added(struct LNchannel *lnchn, struct htlc *htlc,
			     struct LNchannel *only_dest)
{
	struct invoice *invoice;
	struct onionpacket *packet;
	struct route_step *step = NULL;

	if (abs_locktime_is_seconds(&htlc->expiry)) {
		log_unusual(lnchn->log, "HTLC %"PRIu64" is in seconds", htlc->id);
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "bad locktime");
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) <=
	    get_block_height(lnchn->dstate->topology) + lnchn->dstate->config.min_htlc_expiry) {
		log_unusual(lnchn->log, "HTLC %"PRIu64" expires too soon:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "expiry too soon");
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) >
	    get_block_height(lnchn->dstate->topology) + lnchn->dstate->config.max_htlc_expiry) {
		log_unusual(lnchn->log, "HTLC %"PRIu64" expires too far:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "expiry too far");
		return;
	}

	packet = parse_onionpacket(lnchn,
				   htlc->routing, tal_count(htlc->routing));
	if (packet) {
		u8 shared_secret[32];

		if (onion_shared_secret(shared_secret, packet,
					lnchn->dstate->privkey))
			step = process_onionpacket(packet, packet,
						   shared_secret,
						   htlc->rhash.u.u8,
						   sizeof(htlc->rhash));
	}

	if (!step) {
		log_unusual(lnchn->log, "Bad onion, failing HTLC %"PRIu64,
			    htlc->id);
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "invalid onion");
		goto free_packet;
	}

	switch (step->nextcase) {
	case ONION_END:
		if (only_dest)
			goto free_packet;
		invoice = find_unpaid(lnchn->dstate->invoices, &htlc->rhash);
		if (!invoice) {
			log_unusual(lnchn->log, "No invoice for HTLC %"PRIu64,
				    htlc->id);
			log_add_struct(lnchn->log, " rhash=%s",
				       struct sha256, &htlc->rhash);
			if (unlikely(!lnchn->dstate->dev_never_routefail))
				command_htlc_set_fail(lnchn, htlc,
						      UNAUTHORIZED_401,
						      "unknown rhash");
			goto free_packet;
		}

		if (htlc->msatoshi != invoice->msatoshi) {
			log_unusual(lnchn->log, "Short payment for '%s' HTLC %"PRIu64
				    ": %"PRIu64" not %"PRIu64 " satoshi!",
				    invoice->label,
				    htlc->id,
				    htlc->msatoshi,
				    invoice->msatoshi);
			command_htlc_set_fail(lnchn, htlc,
					      UNAUTHORIZED_401,
					      "incorrect amount");
			goto free_packet;
		}

		log_info(lnchn->log, "Immediately resolving '%s' HTLC %"PRIu64,
			 invoice->label, htlc->id);

		resolve_invoice(lnchn->dstate, invoice);
		set_htlc_rval(lnchn, htlc, &invoice->r);
		command_htlc_fulfill(lnchn, htlc);
		goto free_packet;

	case ONION_FORWARD:
		route_htlc_onwards(lnchn, htlc, step->hoppayload->amt_to_forward, step->next->nexthop,
				   serialize_onionpacket(step, step->next), only_dest);
		goto free_packet;
	default:
		log_info(lnchn->log, "Unknown step type %u", step->nextcase);
		command_htlc_set_fail(lnchn, htlc, VERSION_NOT_SUPPORTED_505,
				      "unknown step type");
		goto free_packet;
	}

free_packet:
	tal_free(packet);
}

static void our_htlc_failed(struct LNchannel *lnchn, struct htlc *htlc)
{
	assert(htlc_owner(htlc) == LOCAL);
	if (htlc->src) {
		set_htlc_fail(htlc->src->lnchn, htlc->src,
			      htlc->fail, tal_count(htlc->fail));
		command_htlc_fail(htlc->src->lnchn, htlc->src);
	} else
		complete_pay_command(lnchn->dstate, htlc);
}

static void our_htlc_fulfilled(struct LNchannel *lnchn, struct htlc *htlc)
{
	if (htlc->src) {
		set_htlc_rval(htlc->src->lnchn, htlc->src, htlc->r);
		command_htlc_fulfill(htlc->src->lnchn, htlc->src);
	} else {
		complete_pay_command(lnchn->dstate, htlc);
	}
}

/* FIXME: Slow! */
static struct htlc *htlc_with_source(struct LNchannel *lnchn, struct htlc *src)
{
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (h->src == src)
			return h;
	}
	return NULL;
}

/* lnchn has come back online: re-send any we have to send to them. */
static void retry_all_routing(struct LNchannel *restarted_lnchn)
{
	struct LNchannel *lnchn;
	struct htlc_map_iter it;
	struct htlc *h;

	/* Look for added htlcs from other lnchns which need to go here. */
	list_for_each(&restarted_lnchn->dstate->lnchns, lnchn, list) {
		if (lnchn == restarted_lnchn)
			continue;

		for (h = htlc_map_first(&lnchn->htlcs, &it);
		     h;
		     h = htlc_map_next(&lnchn->htlcs, &it)) {
			if (h->state != RCVD_ADD_ACK_REVOCATION)
				continue;
			if (htlc_with_source(lnchn, h))
				continue;
			their_htlc_added(lnchn, h, restarted_lnchn);
		}
	}

	/* Catch any HTLCs which are fulfilled, but the message got reset
	 * by reconnect. */
	for (h = htlc_map_first(&restarted_lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&restarted_lnchn->htlcs, &it)) {
		if (h->state != RCVD_ADD_ACK_REVOCATION)
			continue;
		if (h->r)
			command_htlc_fulfill(restarted_lnchn, h);
		else if (h->fail)
			command_htlc_fail(restarted_lnchn, h);
	}
}

static bool adjust_cstate_side(struct channel_state *cstate,
			       struct htlc *h,
			       enum htlc_state old, enum htlc_state new,
			       enum side side)
{
	int oldf = htlc_state_flags(old), newf = htlc_state_flags(new);
	bool old_committed, new_committed;

	/* We applied changes to staging_cstate when we first received
	 * add/remove packet, so we could make sure it was valid.  Don't
	 * do that again. */
	if (old == SENT_ADD_HTLC || old == RCVD_REMOVE_HTLC
	    || old == RCVD_ADD_HTLC || old == SENT_REMOVE_HTLC)
		return true;

	old_committed = (oldf & HTLC_FLAG(side, HTLC_F_COMMITTED));
	new_committed = (newf & HTLC_FLAG(side, HTLC_F_COMMITTED));

	if (old_committed && !new_committed) {
		if (h->r)
			cstate_fulfill_htlc(cstate, h);
		else
			cstate_fail_htlc(cstate, h);
	} else if (!old_committed && new_committed) {
		if (!cstate_add_htlc(cstate, h, false)) {
			log_broken_struct(h->lnchn->log,
					  "Cannot afford htlc %s",
					  struct htlc, h);
			log_add_struct(h->lnchn->log, " channel state %s",
				       struct channel_state, cstate);
			return false;
		}
	}
	return true;
}

/* We apply changes to staging_cstate when we first PENDING, so we can
 * make sure they're valid.  So here we change the staging_cstate on
 * the revocation receive (ie. when acked). */
static bool adjust_cstates(struct LNchannel *lnchn, struct htlc *h,
			   enum htlc_state old, enum htlc_state new)
{
	return adjust_cstate_side(lnchn->remote.staging_cstate, h, old, new,
				  REMOTE)
		&& adjust_cstate_side(lnchn->local.staging_cstate, h, old, new,
				      LOCAL);
}

static void adjust_cstate_fee_side(struct channel_state *cstate,
				   const struct feechange *f,
				   enum feechange_state old,
				   enum feechange_state new,
				   enum side side)
{
	/* We applied changes to staging_cstate when we first received
	 * feechange packet, so we could make sure it was valid.  Don't
	 * do that again. */
	if (old == SENT_FEECHANGE || old == RCVD_FEECHANGE)
		return;

	/* Feechanges only ever get applied to the side which created them:
	 * ours gets applied when they ack, theirs gets applied when we ack. */
	if (side == LOCAL && new == RCVD_FEECHANGE_REVOCATION)
		adjust_fee(cstate, f->fee_rate);
	else if (side == REMOTE && new == SENT_FEECHANGE_REVOCATION)
		adjust_fee(cstate, f->fee_rate);
}

static void adjust_cstates_fee(struct LNchannel *lnchn, const struct feechange *f,
			       enum feechange_state old,
			       enum feechange_state new)
{
	adjust_cstate_fee_side(lnchn->remote.staging_cstate, f, old, new, REMOTE);
	adjust_cstate_fee_side(lnchn->local.staging_cstate, f, old, new, LOCAL);
}

static void check_both_committed(struct LNchannel *lnchn, struct htlc *h)
{
	if (!htlc_has(h, HTLC_ADDING) && !htlc_has(h, HTLC_REMOVING))
		log_debug(lnchn->log,
			  "Both committed to %s of %s HTLC %"PRIu64 "(%s)",
			  h->state == SENT_ADD_ACK_REVOCATION
			  || h->state == RCVD_ADD_ACK_REVOCATION ? "ADD"
			  : h->r ? "FULFILL" : "FAIL",
			  htlc_owner(h) == LOCAL ? "our" : "their",
			  h->id, htlc_state_name(h->state));

	switch (h->state) {
	case RCVD_REMOVE_ACK_REVOCATION:
		/* If it was fulfilled, we handled it immediately. */
		if (h->fail)
			our_htlc_failed(lnchn, h);
		break;
	case RCVD_ADD_ACK_REVOCATION:
		their_htlc_added(lnchn, h, NULL);
		break;
	default:
		break;
	}
}

struct htlcs_table {
	enum htlc_state from, to;
};

struct feechanges_table {
	enum feechange_state from, to;
};

static const char *changestates(struct LNchannel *lnchn,
				const struct htlcs_table *table,
				size_t n,
				const struct feechanges_table *ftable,
				size_t n_ftable,
				bool db_commit)
{
	struct htlc_map_iter it;
	struct htlc *h;
	bool changed = false;
	size_t i;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		for (i = 0; i < n; i++) {
			if (h->state == table[i].from) {
				if (!adjust_cstates(lnchn, h,
						    table[i].from, table[i].to))
					return "accounting error";
				htlc_changestate(h, table[i].from,
						 table[i].to, db_commit);
				check_both_committed(lnchn, h);
				changed = true;
			}
		}
	}

	for (i = 0; i < n_ftable; i++) {
		struct feechange *f = lnchn->feechanges[ftable[i].from];
		if (!f)
			continue;
		adjust_cstates_fee(lnchn, f, ftable[i].from, ftable[i].to);
		feechange_changestate(lnchn, f,
				      ftable[i].from, ftable[i].to,
				      db_commit);
		changed = true;
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (!changed)
		return "no changes made";
	return NULL;
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

	ci = new_commit_info(lnchn, lnchn->local.commit->commit_num + 1);

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

static void set_feechange(struct LNchannel *lnchn, u64 fee_rate,
			  enum feechange_state state)
{
	/* If we already have a feechange for this commit, simply update it. */
	if (lnchn->feechanges[state]) {
		log_debug(lnchn->log, "Feechange: fee %"PRIu64" to %"PRIu64,
			  lnchn->feechanges[state]->fee_rate,
			  fee_rate);
		lnchn->feechanges[state]->fee_rate = fee_rate;
	} else {
		log_debug(lnchn->log, "Feechange: New fee %"PRIu64, fee_rate);
		lnchn->feechanges[state] = new_feechange(lnchn, fee_rate, state);
	}
}

static Pkt *handle_pkt_feechange(struct LNchannel *lnchn, const Pkt *pkt)
{
	u64 feerate;
	Pkt *err;

	err = accept_pkt_update_fee(lnchn, pkt, &feerate);
	if (err)
		return err;

	/* FIXME-OLD #2:
	 *
	 * The sending node MUST NOT send a `fee_rate` which it could not
	 * afford (see "Fee Calculation), were it applied to the receiving
	 * node's commitment transaction.  The receiving node SHOULD fail the
	 * connection if this occurs.
	 */
	if (!can_afford_feerate(lnchn->local.staging_cstate, feerate, REMOTE))
		return pkt_err(lnchn, "Cannot afford feerate %"PRIu64,
			       feerate);

	set_feechange(lnchn, feerate, RCVD_FEECHANGE);
	return NULL;
}

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

static bool do_commit(struct LNchannel *lnchn, struct command *jsoncmd)
{
	struct commit_info *ci;
	const char *errmsg;
	static const struct htlcs_table changes[] = {
		{ SENT_ADD_HTLC, SENT_ADD_COMMIT },
		{ SENT_REMOVE_REVOCATION, SENT_REMOVE_ACK_COMMIT },
		{ SENT_ADD_REVOCATION, SENT_ADD_ACK_COMMIT},
		{ SENT_REMOVE_HTLC, SENT_REMOVE_COMMIT}
	};
	static const struct feechanges_table feechanges[] = {
		{ SENT_FEECHANGE, SENT_FEECHANGE_COMMIT },
		{ SENT_FEECHANGE_REVOCATION, SENT_FEECHANGE_ACK_COMMIT}
	};
	bool to_us_only;

	/* We can have changes we suggested, or changes they suggested. */
	if (!lnchn_uncommitted_changes(lnchn)) {
		log_debug(lnchn->log, "do_commit: no changes to commit");
		if (jsoncmd)
			command_fail(jsoncmd, "no changes to commit");
		return true;
	}

	log_debug(lnchn->log, "do_commit: sending commit command %"PRIu64,
		  lnchn->remote.commit->commit_num + 1);

	assert(state_can_commit(lnchn->state));
	assert(!lnchn->commit_jsoncmd);

	lnchn->commit_jsoncmd = jsoncmd;
	ci = new_commit_info(lnchn, lnchn->remote.commit->commit_num + 1);

	assert(!lnchn->their_prev_revocation_hash);
	lnchn->their_prev_revocation_hash
		= tal_dup(lnchn, struct sha256,
			  &lnchn->remote.commit->revocation_hash);

	db_start_transaction(lnchn);

	errmsg = changestates(lnchn, changes, ARRAY_SIZE(changes),
			      feechanges, ARRAY_SIZE(feechanges), true);
	if (errmsg) {
		log_broken(lnchn->log, "queue_pkt_commit: %s", errmsg);
		goto database_error;
	}

	/* Create new commit info for this commit tx. */
	ci->revocation_hash = lnchn->remote.next_revocation_hash;
	/* FIXME-OLD #2:
	 *
	 * ...a sending node MUST apply all remote acked and unacked
	 * changes except unacked fee changes to the remote commitment
	 * before generating `sig`. */
	ci->cstate = copy_cstate(ci, lnchn->remote.staging_cstate);
	ci->tx = create_commit_tx(ci, lnchn, &ci->revocation_hash,
				  ci->cstate, REMOTE, &to_us_only);
	bitcoin_txid(ci->tx, &ci->txid);

	if (!to_us_only) {
		log_debug(lnchn->log, "Signing tx %"PRIu64, ci->commit_num);
		log_add_struct(lnchn->log, " for %s",
			       struct channel_state, ci->cstate);
		log_add_struct(lnchn->log, " (txid %s)",
			       struct sha256_double, &ci->txid);

		ci->sig = tal(ci, ecdsa_signature);
		lnchn_sign_theircommit(lnchn, ci->tx, ci->sig);
	}

	/* Switch to the new commitment. */
	tal_free(lnchn->remote.commit);
	lnchn->remote.commit = ci;
	lnchn->remote.commit->order = lnchn->order_counter++;
	db_new_commit_info(lnchn, REMOTE, lnchn->their_prev_revocation_hash);

	/* We don't need to remember their commit if we don't give sig. */
	if (ci->sig)
		lnchn_add_their_commit(lnchn, &ci->txid, ci->commit_num);

	if (lnchn->state == STATE_SHUTDOWN) {
		set_lnchn_state(lnchn, STATE_SHUTDOWN_COMMITTING, __func__, true);
	} else {
		assert(lnchn->state == STATE_NORMAL);
		set_lnchn_state(lnchn, STATE_NORMAL_COMMITTING, __func__, true);
	}
	if (db_commit_transaction(lnchn) != NULL)
		goto database_error;

	queue_pkt_commit(lnchn, ci->sig);
	return true;

database_error:
	db_abort_transaction(lnchn);
	lnchn_fail(lnchn, __func__);
	return false;
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

/* This is the io loop while we're in normal mode. */
static bool normal_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err = NULL;

	assert(lnchn->state == STATE_NORMAL
	       || lnchn->state == STATE_NORMAL_COMMITTING);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_ADD_HTLC:
		err = handle_pkt_htlc_add(lnchn, pkt);
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

	case PKT__PKT_CLOSE_SHUTDOWN:
		err = accept_pkt_close_shutdown(lnchn, pkt);
		if (err)
			break;
		if (!lnchn_start_shutdown(lnchn)) {
			err = pkt_err(lnchn, "database error");
			break;
		}
		return true;

	case PKT__PKT_UPDATE_REVOCATION:
		if (lnchn->state == STATE_NORMAL_COMMITTING) {
			err = handle_pkt_revocation(lnchn, pkt, STATE_NORMAL);
			if (!err)
				lnchn_update_complete(lnchn);
			break;
		}
		/* Fall thru. */
	default:
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);
	}

	if (err) {
		return lnchn_comms_err(lnchn, err);
	}

	return true;
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

/*
 * This only works because we send one update at a time, and they can't
 * ask for it again if they've already sent the `update_revocation` acking it.
 */
static void retransmit_updates(struct LNchannel *lnchn)
{
	struct htlc_map_iter it;
	struct htlc *h;

	/* FIXME-OLD #2:
	 *
	 * A node MAY simply retransmit messages which are identical to the
	 * previous transmission. */
	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		switch (h->state) {
		case SENT_ADD_COMMIT:
			log_debug(lnchn->log, "Retransmitting add HTLC %"PRIu64,
				  h->id);
			queue_pkt_htlc_add(lnchn, h);
			break;
		case SENT_REMOVE_COMMIT:
			log_debug(lnchn->log, "Retransmitting %s HTLC %"PRIu64,
				  h->r ? "fulfill" : "fail", h->id);
			if (h->r)
				queue_pkt_htlc_fulfill(lnchn, h);
			else
				queue_pkt_htlc_fail(lnchn, h);
			break;
		default:
			break;
		}
	}

	assert(!lnchn->feechanges[SENT_FEECHANGE]);
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

static void retransmit_pkts(struct LNchannel *lnchn, s64 ack)
{
	log_debug(lnchn->log, "Our order counter is %"PRIi64", their ack %"PRIi64,
		  lnchn->order_counter, ack);

	if (ack > lnchn->order_counter) {
		log_unusual(lnchn->log, "reconnect ack %"PRIi64" > %"PRIi64,
			    ack, lnchn->order_counter);
		lnchn_comms_err(lnchn, pkt_err(lnchn, "invalid ack"));
		return;
	}

	log_debug(lnchn->log, "They acked %"PRIi64", remote=%"PRIi64" local=%"PRIi64,
		  ack, lnchn->remote.commit ? lnchn->remote.commit->order : -2,
		  lnchn->local.commit ? lnchn->local.commit->order : -2);

	/* FIXME-OLD #2:
	 *
	 * A node MAY assume that only one of each type of message need be
	 * retransmitted.  A node SHOULD retransmit the last of each message
	 * type which was not counted by the `ack` field.
	 */
	while (ack < lnchn->order_counter) {
		if (ack == 0) {
			queue_pkt_open(lnchn, lnchn->local.offer_anchor);
		} else if (ack == 1) {
			queue_pkt_open_commit_sig(lnchn);
		} else if (lnchn->remote.commit
			   && ack == lnchn->remote.commit->order) {
			/* FIXME-OLD #2:
			 *
			 * Before retransmitting `update_commit`, the node
			 * MUST send appropriate `update_add_htlc`,
			 * `update_fee`, `update_fail_htlc` or
			 * `update_fulfill_htlc` messages (the other node will
			 * have forgotten them, as required above).
			 */
			retransmit_updates(lnchn);
			queue_pkt_commit(lnchn, lnchn->remote.commit->sig);
		} else if (lnchn->local.commit
			   && ack == lnchn->local.commit->order) {
			/* Re-transmit revocation. */
			struct sha256 preimage, next;
			u64 commit_num = lnchn->local.commit->commit_num - 1;

			/* Make sure we don't revoke current commit! */
			assert(commit_num < lnchn->local.commit->commit_num);
			lnchn_get_revocation_preimage(lnchn, commit_num,&preimage);
			lnchn_get_revocation_hash(lnchn, commit_num + 2, &next);
			log_debug(lnchn->log, "Re-sending revocation hash %"PRIu64,
				  commit_num + 2);
			log_add_struct(lnchn->log, "value %s", struct sha256,
				       &next);
			log_add_struct(lnchn->log, "local.next=%s", struct sha256,
				       &lnchn->local.next_revocation_hash);
			log_debug(lnchn->log, "Re-sending revocation %"PRIu64,
				  commit_num);
			queue_pkt_revocation(lnchn, &preimage, &next);
		} else if (ack == lnchn->closing.shutdown_order) {
			log_debug(lnchn->log, "Re-sending shutdown");
			queue_pkt_close_shutdown(lnchn);
		} else if (ack == lnchn->closing.closing_order) {
			log_debug(lnchn->log, "Re-sending closing order");
			queue_pkt_close_signature(lnchn);
		} else {
			log_broken(lnchn->log, "Can't rexmit %"PRIu64
				   " when local commit %"PRIi64" and remote %"PRIi64,
				   ack,
				   lnchn->local.commit ? lnchn->local.commit->order : -2,
				   lnchn->remote.commit ? lnchn->remote.commit->order : -2);
			lnchn_comms_err(lnchn, pkt_err(lnchn, "invalid ack"));
			return;
		}
		ack++;
	}

	/* We might need to update HTLCs which were from other lnchns. */
	retry_all_routing(lnchn);
}

static u64 desired_commit_feerate(struct lightningd_state *dstate)
{
	return get_feerate(dstate->topology) * dstate->config.commitment_fee_percent / 100;
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

static void lnchn_has_connected(struct LNchannel *lnchn)
{
	assert(!lnchn->connected);
	lnchn->connected = true;

	/* Do we want to send something? */
	if (lnchn_uncommitted_changes(lnchn) || want_feechange(lnchn)) {
		log_debug(lnchn->log, "connected: changes pending");
		remote_changes_pending(lnchn);
	}
}

static u64 lnchn_commitsigs_received(struct LNchannel *lnchn)
{
	return lnchn->their_commitsigs;
}

static u64 lnchn_revocations_received(struct LNchannel *lnchn)
{
	/* How many preimages we've received. */
	return -lnchn->their_preimages.min_index;
}

static struct io_plan *lnchn_send_init(struct io_conn *conn, struct LNchannel *lnchn)
{
	u64 open, sigs, revokes, shutdown, closing;

	open = (lnchn->state == STATE_OPEN_WAIT_FOR_OPENPKT ? 0 : 1);
	sigs = lnchn_commitsigs_received(lnchn);
	revokes = lnchn_revocations_received(lnchn);
	shutdown = lnchn->closing.their_script ? 1 : 0;
	closing = lnchn->closing.sigs_in;
	log_debug(lnchn->log,
		  "Init with ack %"PRIu64" opens + %"PRIu64" sigs + %"
		  PRIu64" revokes + %"PRIu64" shutdown + %"PRIu64" closing",
		  open, sigs, revokes, shutdown, closing);

	/* FIXME-OLD #2:
	 *
	 * A node MUST send an `init` message immediately immediately after
	 * it has validated the `authenticate` message.  A node MUST set
	 * the `ack` field in the `init` message to the the sum of
	 * previously-processed messages of types `open`, `open_commit_sig`,
	 * `update_commit`, `update_revocation`, `close_shutdown` and
	 * `close_signature`. */
	return lnchn_write_packet(conn, lnchn,
				 pkt_init(lnchn, open + sigs + revokes
					  + shutdown + closing),
				 read_init_pkt);
}

static bool select_wallet_address_bystr(struct lightningd_state *dstate,
    struct bitcoin_address *addr)
{
    bool   istestnet;
    char  *redeem_addr_str;
    int    i;

    for (i = 0;;++i)
    {
        switch (i)
        {
        case 0:
            redeem_addr_str = dstate->default_redeem_address;
            log_debug(dstate->base_log, "Try redeem address from config ...");
            break;
        case 1:
            /* TODO: not defined yet */
            redeem_addr_str = NULL;
            log_debug(dstate->base_log, "Try redeem address from node wallet ...");
            break;
        case 2:
            redeem_addr_str = bitcoin_redeem_address;
            log_debug(dstate->base_log, "Try redeem address from bitcoind ...");
        default:
            return false;
        }

        if (!redeem_addr_str)
        {
            log_debug(dstate->base_log, "Not defined!");
            continue;
        }

        if (!bitcoin_from_base58(&istestnet, addr, redeem_addr_str,
            strlen(redeem_addr_str)))
        {
            log_debug(dstate->base_log, "Invalid redeem address %s", redeem_addr_str);
            continue;
        }

        if (istestnet != dstate->testnet)
        {   
            log_debug(dstate->base_log,  "Not match for the nettype: is %s address", 
                (istestnet ? "[testnet]" : "[mainnet]"));
            continue;
        }

        return true;
    }

}

/* 3 modes: 1 for native P2WPKH, 2 for P2SH-P2WPKH, other (e.g.: 0) for P2PKH*/
static u8 *gen_redeemscript_from_wallet_str(const tal_t *ctx, 
              struct bitcoin_address *addr, int mode)
{
    switch (mode)
    {
    case 1:
        return bitcoin_redeem_p2wpkh_by_addr(ctx, addr);
    case 2:
        return scriptpubkey_p2sh_p2wpkh(ctx, addr); 
    default:              
        return scriptpubkey_p2pkh(ctx, addr); 
    }

}

static void destroy_lnchn(struct LNchannel *lnchn)
{
	if (lnchn->conn)
		io_close(lnchn->conn);
	list_del_from(&lnchn->dstate->lnchns, &lnchn->list);
}

static void try_reconnect(struct LNchannel *lnchn);

static void lnchn_disconnect(struct io_conn *conn, struct LNchannel *lnchn)
{
	log_info(lnchn->log, "Disconnected");

	/* No longer connected. */
	lnchn->conn = NULL;
	lnchn->connected = false;

	/* Not even set up yet?  Simply free.*/
	if (lnchn->state == STATE_INIT) {
		/* This means we didn't get past crypto handshake or hit db */
		tal_free(lnchn);
		return;
	}

	/* Completely dead?  Free it now. */
	if (lnchn->state == STATE_CLOSED) {
		io_break(lnchn);
		return;
	}

	/* This is an unexpected close. */
	if (state_can_io(lnchn->state)) {
		forget_uncommitted_changes(lnchn);
		try_reconnect(lnchn);
	}
}

static void try_commit(struct LNchannel *lnchn)
{
	lnchn->commit_timer = NULL;

	if (!lnchn->connected) {
		log_debug(lnchn->log, "try_commit: state=%s, not connected",
			  state_name(lnchn->state));
		return;
	}

	if (state_can_commit(lnchn->state))
		do_commit(lnchn, NULL);
	else {
		/* FIXME: try again when we receive revocation /
		 * reconnect, rather than using timer! */
		log_debug(lnchn->log, "try_commit: state=%s, re-queueing timer",
			  state_name(lnchn->state));

		remote_changes_pending(lnchn);
	}
}

struct commit_info *new_commit_info(const tal_t *ctx, u64 commit_num)
{
	struct commit_info *ci = tal(ctx, struct commit_info);
	ci->commit_num = commit_num;
	ci->tx = NULL;
	ci->cstate = NULL;
	ci->sig = NULL;
	ci->order = (s64)-1LL;
	return ci;
}

static bool lnchn_reconnected(struct LNchannel *lnchn,
			     struct io_conn *conn,
			     int addr_type, int addr_protocol,
			     struct io_data *iod,
			     const struct pubkey *id,
			     bool we_connected)
{
	char *name;
	struct netaddr addr;

	assert(structeq(lnchn->id, id));

	lnchn->io_data = tal_steal(lnchn, iod);

	/* FIXME: Attach IO logging for this lnchn. */
	if (!netaddr_from_fd(io_conn_fd(conn), addr_type, addr_protocol, &addr))
		return false;

	/* If we free lnchn, conn should be closed, but can't be freed
	 * immediately so don't make lnchn a parent. */
	lnchn->conn = conn;
	io_set_finish(conn, lnchn_disconnect, lnchn);

	name = netaddr_name(lnchn, &addr);
	log_info(lnchn->log, "Reconnected %s %s",
		 we_connected ? "out to" : "in from", name);
	tal_free(name);

	return true;
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
	lnchn->order_counter = 0;
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

	htlc_map_init(&lnchn->htlcs);
	memset(lnchn->feechanges, 0, sizeof(lnchn->feechanges));
	shachain_init(&lnchn->their_preimages);

	tal_add_destructor(lnchn, destroy_lnchn);
	return lnchn;
}

static bool lnchn_first_connected(struct LNchannel *lnchn,
				 struct io_conn *conn,
				 int addr_type, int addr_protocol,
				 struct io_data *iod,
				 const struct pubkey *id,
				 bool we_connected)
{
	char *name, *idstr;
	struct netaddr addr;

	lnchn->io_data = tal_steal(lnchn, iod);
	lnchn->id = tal_dup(lnchn, struct pubkey, id);
	lnchn->local.commit_fee_rate = desired_commit_feerate(lnchn->dstate);

	lnchn->htlc_id_counter = 0;

	/* If we free lnchn, conn should be closed, but can't be freed
	 * immediately so don't make lnchn a parent. */
	lnchn->conn = conn;
	io_set_finish(conn, lnchn_disconnect, lnchn);

	lnchn->anchor.min_depth = get_block_height(lnchn->dstate->topology);

	/* FIXME: Attach IO logging for this lnchn. */
	if (!netaddr_from_fd(io_conn_fd(conn), addr_type, addr_protocol, &addr))
		return false;

	/* Save/update address if we connected to them. */
	if (we_connected && !add_lnchn_address(lnchn->dstate, lnchn->id, &addr))
		return false;

	name = netaddr_name(lnchn, &addr);
	idstr = pubkey_to_hexstr(name, lnchn->id);
	log_info(lnchn->log, "Connected %s %s id %s, changing prefix",
		 we_connected ? "out to" : "in from", name, idstr);
	set_log_prefix(lnchn->log, tal_fmt(name, "%s:", idstr));
	tal_free(name);

	log_debug(lnchn->log, "Using fee rate %"PRIu64,
		  lnchn->local.commit_fee_rate);
	return true;
}

static void htlc_destroy(struct htlc *htlc)
{
	if (!htlc_map_del(&htlc->lnchn->htlcs, htlc))
		fatal("Could not find htlc to destroy");
}

struct htlc *lnchn_new_htlc(struct LNchannel *lnchn,
			   u64 msatoshi,
			   const struct sha256 *rhash,
			   u32 expiry, u32 src_expiry,
			   enum htlc_state state)
{
	struct htlc *h = tal(lnchn, struct htlc);
	h->state = state;
	h->msatoshi = msatoshi;
	h->rhash = *rhash;
	h->r = NULL;
	h->fail = NULL;
    h->src_expiry = NULL;
	if (!blocks_to_abs_locktime(expiry, &h->expiry))
		fatal("Invalid HTLC expiry %u", expiry);
	if (htlc_owner(h) == LOCAL) {
		if (src_expiry != 0) {
            h->src_expiry = tal(h, struct abs_locktime);
	        if (!blocks_to_abs_locktime(src_expiry, h->src_expiry))
		        fatal("Invalid source HTLC expiry %u", src_expiry);
			h->deadline = abs_locktime_to_blocks(src_expiry)
				- lnchn->dstate->config.deadline_blocks;            
		} else
			/* If we're paying, give it a little longer. */
			h->deadline = expiry
				+ lnchn->dstate->config.min_htlc_expiry;
	} else {
		assert(htlc_owner(h) == REMOTE);
	}
	htlc_map_add(&lnchn->htlcs, h);
	tal_add_destructor(h, htlc_destroy);

    lite_reg_htlc(lnchn->dstate->channels, lnchn, h);

	return h;
}

static struct io_plan *crypto_on_reconnect(struct io_conn *conn,
					   struct lightningd_state *dstate,
					   struct io_data *iod,
					   const struct pubkey *id,
					   struct LNchannel *lnchn,
					   bool we_connected)
{
	/* Setup lnchn->conn and lnchn->io_data */
	if (!lnchn_reconnected(lnchn, conn, SOCK_STREAM, IPPROTO_TCP,
			      iod, id, we_connected))
		return io_close(conn);

	/* We need to eliminate queue now. */
	clear_output_queue(lnchn);

	return lnchn_send_init(conn, lnchn);
}

static struct io_plan *crypto_on_reconnect_in(struct io_conn *conn,
					      struct lightningd_state *dstate,
					      struct io_data *iod,
					      struct log *log,
					      const struct pubkey *id,
					      struct LNchannel *lnchn)
{
	assert(log == lnchn->log);
	return crypto_on_reconnect(conn, dstate, iod, id, lnchn, false);
}

static struct io_plan *crypto_on_reconnect_out(struct io_conn *conn,
					       struct lightningd_state *dstate,
					       struct io_data *iod,
					       struct log *log,
					       const struct pubkey *id,
					       struct LNchannel *lnchn)
{
	assert(log == lnchn->log);
	return crypto_on_reconnect(conn, dstate, iod, id, lnchn, true);
}

static struct io_plan *crypto_on_out(struct io_conn *conn,
				     struct lightningd_state *dstate,
				     struct io_data *iod,
				     struct log *log,
				     const struct pubkey *id,
				     struct json_connecting *connect)
{
	struct LNchannel *lnchn;

	if (find_lnchn(dstate, id)) {
		command_fail(connect->cmd, "Already connected to lnchn %s",
			     pubkey_to_hexstr(connect->cmd, id));
		return io_close(conn);
	}

	/* Initiator currently funds channel */
	lnchn = new_lnchn(dstate, log, STATE_INIT, true);
	if (!lnchn_first_connected(lnchn, conn, SOCK_STREAM, IPPROTO_TCP,
				  iod, id, true)) {
		command_fail(connect->cmd, "Failed to make lnchn for %s:%s",
			     connect->name, connect->port);
		return io_close(conn);
	}
	lnchn->anchor.input = tal_steal(lnchn, connect->input);
	lnchn->open_jsoncmd = connect->cmd;
	return lnchn_crypto_on(conn, lnchn);
}

static struct io_plan *lnchn_connected_out(struct io_conn *conn,
					  struct lightningd_state *dstate,
					  const struct netaddr *netaddr,
					  struct json_connecting *connect)
{
	struct log *l;

	l = new_log(conn, dstate->log_book, "OUT-%s:%s:",
		    connect->name, connect->port);

	log_debug_struct(l, "Connected out to %s", struct netaddr, netaddr);
	return lnchn_crypto_setup(conn, dstate, NULL, l, crypto_on_out, connect);
}

static struct io_plan *crypto_on_in(struct io_conn *conn,
				    struct lightningd_state *dstate,
				    struct io_data *iod,
				    struct log *log,
				    const struct pubkey *id,
				    void *unused)
{
	struct LNchannel *lnchn;

	/* FIXME-OLD #2:
	 *
	 * A node MUST handle continuing a previous channel on a new encrypted
	 * transport. */
	lnchn = find_lnchn(dstate, id);
	if (lnchn) {
		/* Close any existing connection, without side effects. */
		if (lnchn->conn) {
			log_debug(log, "This is reconnect for lnchn %p", lnchn);
			log_debug(lnchn->log, "Reconnect: closing old conn %p for new conn %p",
				  lnchn->conn, conn);
			io_set_finish(lnchn->conn, NULL, NULL);
			io_close(lnchn->conn);
			lnchn->conn = NULL;
			lnchn->connected = false;
		}
		return crypto_on_reconnect_in(conn, dstate, iod, lnchn->log, id,
					      lnchn);
	}

	/* Initiator currently funds channel */
	lnchn = new_lnchn(dstate, log, STATE_INIT, false);
	if (!lnchn_first_connected(lnchn, conn, SOCK_STREAM, IPPROTO_TCP,
				  iod, id, false))
		return io_close(conn);

	return lnchn_crypto_on(conn, lnchn);
}

static struct io_plan *lnchn_connected_in(struct io_conn *conn,
					 struct lightningd_state *dstate)
{
	struct netaddr addr;
	struct log *l;
	const char *name;

	if (!netaddr_from_fd(io_conn_fd(conn), SOCK_STREAM, IPPROTO_TCP, &addr))
		return false;
	name = netaddr_name(conn, &addr);
	l = new_log(conn, dstate->log_book, "IN-%s:", name);

	log_debug(l, "Connected in");

	return lnchn_crypto_setup(conn, dstate, NULL, l, crypto_on_in, NULL);
}


static void json_connect(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct json_connecting *connect;
	jsmntok_t *host, *port, *txtok;
	struct bitcoin_tx *tx;
	int output;
	size_t txhexlen;
	u64 fee;
	const tal_t *tmpctx = tal_tmpctx(cmd);

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &port,
			     "tx", &txtok,
			     NULL)) {
		command_fail(cmd, "Need host, port and tx to a wallet address");
		return;
	}

	connect = tal(cmd, struct json_connecting);
	connect->cmd = cmd;
	connect->name = tal_strndup(connect, buffer + host->start,
				    host->end - host->start);
	connect->port = tal_strndup(connect, buffer + port->start,
				    port->end - port->start);
	connect->input = tal(connect, struct anchor_input);

	txhexlen = txtok->end - txtok->start;
	tx = bitcoin_tx_from_hex(tmpctx, buffer + txtok->start, txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			     txtok->end - txtok->start,
			     buffer + txtok->start);
		return;
	}

	bitcoin_txid(tx, &connect->input->txid);

	/* Find an output we know how to spend. */
	for (output = 0; output < tal_count(tx->output); output++) {
		if (wallet_can_spend(cmd->dstate, &tx->output[output],
				     &connect->input->walletkey))
			break;
	}
	if (output == tal_count(tx->output)) {
		command_fail(cmd, "Tx doesn't send to wallet address");
		return;
	}

	connect->input->index = output;
	connect->input->in_amount = tx->output[output].amount;

	/* FIXME: This is normal case, not exact. */
	fee = fee_by_feerate(94 + 1+73 + 1+33 + 1, get_feerate(cmd->dstate->topology));
	if (fee >= connect->input->in_amount) {
		command_fail(cmd, "Amount %"PRIu64" below fee %"PRIu64,
			     connect->input->in_amount, fee);
		return;
	}

	connect->input->out_amount = connect->input->in_amount - fee;
	if (anchor_too_large(connect->input->out_amount)) {
		command_fail(cmd, "Amount %"PRIu64" is too large",
			     connect->input->out_amount);
		return;
	}
	if (!dns_resolve_and_connect(cmd->dstate, connect->name, connect->port,
				     lnchn_connected_out, lnchn_failed, connect)) {
		command_fail(cmd, "DNS failed");
		return;
	}

	tal_free(tmpctx);
}

/* Have any of our HTLCs passed their deadline? */
static bool any_deadline_past(struct LNchannel *lnchn)
{
	u32 height = get_block_height(lnchn->dstate->topology);
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (htlc_is_dead(h))
			continue;
		if (htlc_owner(h) != LOCAL)
			continue;
		if (height >= h->deadline) {
			log_unusual_struct(lnchn->log,
					   "HTLC %s deadline has passed",
					   struct htlc, h);
			return true;
		}
	}
	return false;
}

static void check_htlc_expiry(struct LNchannel *lnchn)
{
	u32 height = get_block_height(lnchn->dstate->topology);
	struct htlc_map_iter it;
	struct htlc *h;

	/* Check their currently still-existing htlcs for expiry */
	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		assert(!abs_locktime_is_seconds(&h->expiry));

		/* Only their consider HTLCs which are completely locked in. */
		if (h->state != RCVD_ADD_ACK_REVOCATION)
			continue;

		/* We give it an extra block, to avoid the worst of the
		 * inter-node timing issues. */
		if (height <= abs_locktime_to_blocks(&h->expiry))
			continue;

		db_start_transaction(lnchn);
		/* This can fail only if we're in an error state. */
		command_htlc_set_fail(lnchn, h,
				      REQUEST_TIMEOUT_408, "timed out");
		if (db_commit_transaction(lnchn) != NULL) {
			lnchn_fail(lnchn, __func__);
			return;
		}
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT offer a HTLC after this deadline, and MUST
	 * fail the connection if an HTLC which it offered is in
	 * either node's current commitment transaction past this
	 * deadline.
	 */

	/* To save logic elsewhere (ie. to avoid signing a new commit with a
	 * past-deadline HTLC) we also check staged HTLCs.
	 */
	if (!state_is_normal(lnchn->state))
		return;

	if (any_deadline_past(lnchn))
		lnchn_fail(lnchn, __func__);
}

static void lnchn_depth_ok(struct LNchannel *lnchn)
{
	queue_pkt_open_complete(lnchn);

	db_start_transaction(lnchn);

	switch (lnchn->state) {
	case STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE:
		set_lnchn_state(lnchn, STATE_OPEN_WAIT_THEIRCOMPLETE,
			       __func__, true);
		break;
	case STATE_OPEN_WAIT_ANCHORDEPTH:
		lnchn_open_complete(lnchn, NULL);
		set_lnchn_state(lnchn, STATE_NORMAL, __func__, true);
		announce_channel(lnchn->dstate, lnchn);
		sync_routing_table(lnchn->dstate, lnchn);
		break;
	default:
		log_broken(lnchn->log, "%s: state %s",
			   __func__, state_name(lnchn->state));
		lnchn_fail(lnchn, __func__);
		break;
	}

	if (db_commit_transaction(lnchn))
		lnchn_database_err(lnchn);
}

static enum watch_result anchor_depthchange(struct LNchannel *lnchn,
					    unsigned int depth,
					    const struct sha256_double *txid,
					    void *unused)
{
	log_debug(lnchn->log, "Anchor at depth %u", depth);

	/* Still waiting for it to reach depth? */
	if (state_is_waiting_for_anchor(lnchn->state)) {
		log_debug(lnchn->log, "Waiting for depth %i",
			  lnchn->anchor.ok_depth);
		/* We can see a run of blocks all at once, so may be > depth */
		if ((int)depth >= lnchn->anchor.ok_depth) {
			lnchn_depth_ok(lnchn);
			lnchn->anchor.ok_depth = -1;
		}
	} else if (depth == 0)
		/* FIXME: Report losses! */
		fatal("Funding transaction was unspent!");

	/* Since this gets called on every new block, check HTLCs here. */
	check_htlc_expiry(lnchn);

	/* If fee rate has changed, fire off update to change it. */
	if (want_feechange(lnchn) && state_can_commit(lnchn->state)) {
		log_debug(lnchn->log, "fee rate changed to %"PRIu64,
			  desired_commit_feerate(lnchn->dstate));
		/* FIXME: If fee changes back before update, we screw
		 * up and send an empty commit.  We need to generate a
		 * real packet here! */
		remote_changes_pending(lnchn);
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST update bitcoin fees if it estimates that the
	 * current commitment transaction will not be processed in a
	 * timely manner (see "Risks With HTLC Timeouts").
	 */
	/* Note: we don't do this when we're told to ignore fees. */
	/* FIXME: BOLT should say what to do if it can't!  We drop conn. */
	if (!state_is_onchain(lnchn->state) && !state_is_error(lnchn->state)
	    && lnchn->dstate->config.commitment_fee_min_percent != 0
	    && lnchn->local.commit->cstate->fee_rate < get_feerate(lnchn->dstate->topology)) {
		log_broken(lnchn->log, "fee rate %"PRIu64" lower than %"PRIu64,
			   lnchn->local.commit->cstate->fee_rate,
			   get_feerate(lnchn->dstate->topology));
		lnchn_fail(lnchn, __func__);
	}

	return KEEP_WATCHING;
}

void notify_new_block(struct chain_topology *topo, unsigned int height)
{
	struct lightningd_state *dstate = tal_parent(topo);
	/* This is where we check for anchor timeouts. */
	struct LNchannel *lnchn;

	list_for_each(&dstate->lnchns, lnchn, list) {
		if (!state_is_waiting_for_anchor(lnchn->state))
			continue;

		/* If we haven't seen anchor yet, we can timeout. */
		if (height >= lnchn->anchor.min_depth
		    + dstate->config.anchor_onchain_wait
		    + dstate->config.anchor_confirms) {
			queue_pkt_err(lnchn, pkt_err(lnchn, "Funding timeout"));
			set_lnchn_state(lnchn, STATE_ERR_ANCHOR_TIMEOUT, __func__,
				       false);
			lnchn_breakdown(lnchn);
		}
	}
}


/* We usually don't fail HTLCs we offered, but if the lnchn breaks down
 * before we've confirmed it, this is exactly what happens. */
void internal_fail_own_htlc(struct LNchannel *lnchn, struct htlc *htlc)
{
	/* We can't do anything about db failures; lnchn already closed. */
	db_start_transaction(lnchn);
	set_htlc_fail(lnchn, htlc, "lnchn closed", strlen("lnchn closed"));
	our_htlc_failed(lnchn, htlc);
	db_commit_transaction(lnchn);
}


static enum watch_result our_htlc_spent(struct LNchannel *lnchn,
					const struct bitcoin_tx *tx,
					size_t input_num,
					struct htlc *h)
{
	struct sha256 sha;
	struct preimage preimage;

	/* FIXME-OLD #onchain:
	 *
	 * If a node sees a redemption transaction...the node MUST extract the
	 * preimage from the transaction input witness.  This is either to
	 * prove payment (if this node originated the payment), or to redeem
	 * the corresponding incoming HTLC from another lnchn.
	 */

	/* This is the form of all HTLC spends. */
	if (!tx->input[input_num].witness
	    || tal_count(tx->input[input_num].witness) != 3
	    || tal_count(tx->input[input_num].witness[1]) != sizeof(preimage))
		fatal("Impossible HTLC spend for %"PRIu64, h->id);

	/* Our timeout tx has all-zeroes, so we can distinguish it. */
	if (memeqzero(tx->input[input_num].witness[1], sizeof(preimage)))
		/* They might try to race us. */
		return KEEP_WATCHING;

	memcpy(&preimage, tx->input[input_num].witness[1], sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));

	/* FIXME: This could happen with a ripemd collision, since
	 * script.c only checks that ripemd matches... */
	if (!structeq(&sha, &h->rhash))
		fatal("HTLC redeemed with incorrect r value?");

	log_unusual(lnchn->log, "lnchn redeemed HTLC %"PRIu64" on-chain",
		    h->id);
	log_add_struct(lnchn->log, " using rvalue %s", struct preimage, &preimage);

	set_htlc_rval(lnchn, h, &preimage);
	our_htlc_fulfilled(lnchn, h);

	/* FIXME-OLD #onchain:
	 *
	 * If a node sees a redemption transaction, the output is considered
	 * *irrevocably resolved*... Note that we don't care about the fate of
	 * the redemption transaction itself once we've extracted the
	 * preimage; the knowledge is not revocable.
	 */
	lnchn->onchain.resolved[tx->input[input_num].index]
		= irrevocably_resolved(lnchn);
	return DELETE_WATCH;
}

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


/* Return earliest block we're interested in, or 0 for none. */
u32 get_lnchn_min_block(struct lightningd_state *dstate)
{
	u32 min_block = 0;
	struct LNchannel *lnchn;

	/* If loaded from database, go back to earliest possible lnchn anchor. */
	list_for_each(&dstate->lnchns, lnchn, list) {
		if (!lnchn->anchor.min_depth)
			continue;
		if (min_block == 0 || lnchn->anchor.min_depth < min_block)
			min_block = lnchn->anchor.min_depth;
	}
	return min_block;
}

/* We may have gone down before broadcasting the anchor.  Try again. */
void rebroadcast_anchors(struct lightningd_state *dstate)
{
	struct LNchannel *lnchn;

	list_for_each(&dstate->lnchns, lnchn, list) {
		if (!state_is_waiting_for_anchor(lnchn->state))
			continue;
		if (!lnchn->anchor.ours)
			continue;
		if (!bitcoin_create_anchor(lnchn))
			lnchn_fail(lnchn, __func__);
		else
			broadcast_tx(lnchn->dstate->topology,
				     lnchn, lnchn->anchor.tx, NULL);
	}
}

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

static void json_newhtlc(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok, *msatoshitok, *expirytok, *rhashtok;
	unsigned int expiry;
	u64 msatoshi;
	struct sha256 rhash;
	struct json_result *response = new_json_result(cmd);
	struct htlc *htlc;
	const char *err;
	enum fail_error error_code;
	struct hoppayload *hoppayloads;
	u8 sessionkey[32];
	struct onionpacket *packet;
	u8 *onion;
	struct pubkey *path = tal_arrz(cmd, struct pubkey, 1);

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     "msatoshi", &msatoshitok,
			     "expiry", &expirytok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid, msatoshi, expiry and rhash");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->remote.commit || !lnchn->remote.commit->cstate) {
		command_fail(cmd, "lnchn not fully established");
		return;
	}

	if (!lnchn->connected) {
		command_fail(cmd, "lnchn not connected");
		return;
	}

	if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshitok->end - msatoshitok->start),
			     buffer + msatoshitok->start);
		return;
	}
	if (!json_tok_number(buffer, expirytok, &expiry)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(expirytok->end - expirytok->start),
			     buffer + expirytok->start);
		return;
	}

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&rhash, sizeof(rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	tal_arr(cmd, struct pubkey, 1);
	hoppayloads = tal_arrz(cmd, struct hoppayload, 1);
	memcpy(&path[0], lnchn->id, sizeof(struct pubkey));
	randombytes_buf(&sessionkey, sizeof(sessionkey));
	packet = create_onionpacket(cmd, path, hoppayloads, sessionkey,
				    rhash.u.u8, sizeof(rhash));
	onion = serialize_onionpacket(cmd, packet);

	log_debug(lnchn->log, "JSON command to add new HTLC");
	err = command_htlc_add(lnchn, msatoshi, expiry, &rhash, NULL,
			       onion,
			       &error_code, &htlc);
	if (err) {
		command_fail(cmd, "could not add htlc: %u:%s", error_code, err);
		return;
	}
	log_debug(lnchn->log, "JSON new HTLC is %"PRIu64, htlc->id);

	json_object_start(response, NULL);
	json_add_u64(response, "id", htlc->id);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_fulfillhtlc(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok, *idtok, *rtok;
	u64 id;
	struct htlc *htlc;
	struct sha256 rhash;
	struct preimage r;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     "id", &idtok,
			     "r", &rtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid, id and r");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->remote.commit || !lnchn->remote.commit->cstate) {
		command_fail(cmd, "lnchn not fully established");
		return;
	}

	if (!lnchn->connected) {
		command_fail(cmd, "lnchn not connected");
		return;
	}

	if (!json_tok_u64(buffer, idtok, &id)) {
		command_fail(cmd, "'%.*s' is not a valid id",
			     (int)(idtok->end - idtok->start),
			     buffer + idtok->start);
		return;
	}

	if (!hex_decode(buffer + rtok->start,
			rtok->end - rtok->start,
			&r, sizeof(r))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 preimage",
			     (int)(rtok->end - rtok->start),
			     buffer + rtok->start);
		return;
	}

	htlc = htlc_get(&lnchn->htlcs, id, REMOTE);
	if (!htlc) {
		command_fail(cmd, "preimage htlc not found");
		return;
	}

	if (htlc->state != RCVD_ADD_ACK_REVOCATION) {
		command_fail(cmd, "htlc in state %s",
			     htlc_state_name(htlc->state));
		return;
	}

	sha256(&rhash, &r, sizeof(r));
	if (!structeq(&htlc->rhash, &rhash)) {
		command_fail(cmd, "preimage incorrect");
		return;
	}

	/* This can happen if we're disconnected, and thus haven't sent
	 * fulfill yet; we stored r in database immediately. */
	if (!htlc->r) {
		const char *db_err;

		db_start_transaction(lnchn);
		set_htlc_rval(lnchn, htlc, &r);

		/* We can relay this upstream immediately. */
		our_htlc_fulfilled(lnchn, htlc);
		db_err = db_commit_transaction(lnchn);
		if (db_err) {
			command_fail(cmd, "%s", db_err);
			return;
		}
	}

	if (command_htlc_fulfill(lnchn, htlc))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fulfill not possible in state %s",
			     state_name(lnchn->state));
}

static const struct json_command dev_fulfillhtlc_command = {
	"dev-fulfillhtlc",
	json_fulfillhtlc,
	"Redeem htlc proposed by {lnchnid} of {id} using {r}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_fulfillhtlc_command);

static void json_failhtlc(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok, *idtok, *reasontok;
	u64 id;
	struct htlc *htlc;
	const char *db_err;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     "id", &idtok,
			     "reason", &reasontok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid, id and reason");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->remote.commit || !lnchn->remote.commit->cstate) {
		command_fail(cmd, "lnchn not fully established");
		return;
	}

	if (!lnchn->connected) {
		command_fail(cmd, "lnchn not connected");
		return;
	}

	if (!json_tok_u64(buffer, idtok, &id)) {
		command_fail(cmd, "'%.*s' is not a valid id",
			     (int)(idtok->end - idtok->start),
			     buffer + idtok->start);
		return;
	}

	htlc = htlc_get(&lnchn->htlcs, id, REMOTE);
	if (!htlc) {
		command_fail(cmd, "preimage htlc not found");
		return;
	}

	if (htlc->state != RCVD_ADD_ACK_REVOCATION) {
		command_fail(cmd, "htlc in state %s",
			     htlc_state_name(htlc->state));
		return;
	}

	db_start_transaction(lnchn);

	set_htlc_fail(lnchn, htlc, buffer + reasontok->start,
		      reasontok->end - reasontok->start);

	db_err = db_commit_transaction(lnchn);
	if (db_err) {
		command_fail(cmd, "%s", db_err);
		return;
	}

	if (command_htlc_fail(lnchn, htlc))
		command_success(cmd, null_response(cmd));
	else
		command_fail(cmd,
			     "htlc_fail not possible in state %s",
			     state_name(lnchn->state));
}

static const struct json_command dev_failhtlc_command = {
	"dev-failhtlc",
	json_failhtlc,
	"Fail htlc proposed by {lnchnid} which has {id}, using {reason}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_failhtlc_command);

static void json_commit(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok;

	if (!json_get_params(buffer, params,
			    "lnchnid", &lnchnidtok,
			    NULL)) {
		command_fail(cmd, "Need lnchnid");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->remote.commit || !lnchn->remote.commit->cstate) {
		command_fail(cmd, "lnchn not fully established");
		return;
	}

	if (!lnchn->connected) {
		command_fail(cmd, "lnchn not connected");
		return;
	}

	if (!state_can_commit(lnchn->state)) {
		command_fail(cmd, "lnchn in state %s", state_name(lnchn->state));
		return;
	}

	do_commit(lnchn, cmd);
}

static const struct json_command dev_commit_command = {
	"dev-commit",
	json_commit,
	"Commit all staged HTLC changes with {lnchnid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_commit_command);

static void json_close(struct command *cmd,
		       const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!state_is_normal(lnchn->state) && !state_is_opening(lnchn->state)) {
		command_fail(cmd, "lnchn is already closing: state %s",
			     state_name(lnchn->state));
		return;
	}

	if (!lnchn_start_shutdown(lnchn)) {
		command_fail(cmd, "Database error");
		return;
	}
	/* FIXME: Block until closed! */
	command_success(cmd, null_response(cmd));
}

static const struct json_command close_command = {
	"close",
	json_close,
	"Close the channel with lnchn {lnchnid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &close_command);

static void json_feerate(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *feeratetok;
	u64 feerate;

	if (!json_get_params(buffer, params,
			     "feerate", &feeratetok,
			     NULL)) {
		command_fail(cmd, "Need feerate");
		return;
	}

	if (!json_tok_u64(buffer, feeratetok, &feerate)) {
		command_fail(cmd, "Invalid feerate");
		return;
	}
	log_debug(cmd->jcon->log, "Fee rate changed to %"PRIu64, feerate);
	cmd->dstate->topology->default_fee_rate = feerate;

	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_feerate_command = {
	"dev-feerate",
	json_feerate,
	"Change the (default) fee rate to {feerate}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_feerate_command);

static void json_disconnect(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->conn) {
		command_fail(cmd, "lnchn is already disconnected");
		return;
	}

	/* We don't actually close it, since for testing we want only
	 * one side to freak out.  We just ensure we ignore it. */
	log_debug(lnchn->log, "Pretending connection is closed");
	lnchn->fake_close = true;
	lnchn->connected = false;
	lnchn_fail(lnchn, __func__);

	command_success(cmd, null_response(cmd));
}

static void json_reconnect(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->conn) {
		command_fail(cmd, "lnchn is already disconnected");
		return;
	}

	/* Should reconnect on its own. */
	io_close(lnchn->conn);
	command_success(cmd, null_response(cmd));
}

static void json_signcommit(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok;
	u8 *linear;
	struct json_result *response = new_json_result(cmd);

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->local.commit->sig) {
		command_fail(cmd, "lnchn has not given us a signature");
		return;
	}

	sign_commit_tx(lnchn);
	linear = linearize_tx(cmd, lnchn->local.commit->tx);

	/* Clear witness for potential future uses. */
	lnchn->local.commit->tx->input[0].witness
		= tal_free(lnchn->local.commit->tx->input[0].witness);

	json_object_start(response, NULL);
	json_add_string(response, "tx", tal_hex(cmd, linear));
	json_object_end(response);
	command_success(cmd, response);
}

static void json_output(struct command *cmd,
			const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok, *enabletok;
	bool enable;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     "enable", &enabletok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid and enable");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (!lnchn->conn) {
		command_fail(cmd, "lnchn is already disconnected");
		return;
	}

	if (!json_tok_bool(buffer, enabletok, &enable)) {
		command_fail(cmd, "enable must be true or false");
		return;
	}

	log_debug(lnchn->log, "dev-output: output %s",
		  enable ? "enabled" : "disabled");
	lnchn->output_enabled = enable;

	/* Flush any outstanding output */
	if (lnchn->output_enabled)
		io_wake(lnchn);

	command_success(cmd, null_response(cmd));
}
