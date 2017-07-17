
#include "db.h"
#include "log.h"
#include "lnchannel.h"
#include "lnchannel_internal.h"
#include "permute_tx.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "find_p2sh_out.h"
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
	list_add_tail(&lnchn->their_commits, &tc->list);

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

/* Create a bitcoin spend tx (to spend our commit's outputs) */
static const struct bitcoin_tx *bitcoin_spend_ours(struct LNchannel *lnchn)
{
	u8 *witnessscript;
	const struct bitcoin_tx *commit = lnchn->local.commit->tx;
	ecdsa_signature sig;
	struct bitcoin_tx *tx;
	unsigned int p2wsh_out;
	uint64_t fee;

	/* The redeemscript for a commit tx is fairly complex. */
	witnessscript = bitcoin_redeem_secret_or_delay(lnchn,
						      &lnchn->local.finalkey,
						      &lnchn->remote.locktime,
						      &lnchn->remote.finalkey,
						      &lnchn->local.commit->revocation_hash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(lnchn, 1, 1);
	tx->input[0].txid = lnchn->local.commit->txid;
	p2wsh_out = find_p2wsh_out(commit, witnessscript);
	tx->input[0].index = p2wsh_out;
	tx->input[0].sequence_number = bitcoin_nsequence(&lnchn->remote.locktime);
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &commit->output[p2wsh_out].amount);

    tx->output[0].script = lnchn->final_redeemscript;/* scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
						       &lnchn->local.finalkey));*/

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 176 from an example run. */
	assert(measure_tx_cost(tx) == 83 * 4);

	fee = fee_by_feerate(83 + 176 / 4, get_feerate(lnchn->dstate->topology));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > commit->output[p2wsh_out].amount
	    || is_dust(commit->output[p2wsh_out].amount - fee))
		fatal("Amount of %"PRIu64" won't cover fee %"PRIu64,
		      commit->output[p2wsh_out].amount, fee);

	tx->output[0].amount = commit->output[p2wsh_out].amount - fee;

	lnchn_sign_spend(lnchn, tx, witnessscript, &sig);

	tx->input[0].witness = bitcoin_witness_secret(tx,
						      NULL, 0, &sig,
						      witnessscript);

	return tx;
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

struct LNchannel *find_lnchn(struct lightningd_state *dstate, const struct pubkey *id)
{
	struct LNchannel *lnchn;

	list_for_each(&dstate->lnchns, lnchn, list) {
		if (lnchn->id && pubkey_eq(lnchn->id, id))
			return lnchn;
	}
	return NULL;
}

struct LNchannel *find_lnchn_by_pkhash(struct lightningd_state *dstate, const u8 *pkhash)
{
	struct LNchannel *lnchn;
	u8 addr[20];

	list_for_each(&dstate->lnchns, lnchn, list) {
		pubkey_hash160(addr, lnchn->id);
		if (memcmp(addr, pkhash, sizeof(addr)) == 0)
			return lnchn;
	}
	return NULL;
}

void debug_dump_lnchns(struct lightningd_state *dstate)
{
	struct LNchannel *lnchn;

	list_for_each(&dstate->lnchns, lnchn, list) {
		if (!lnchn->local.commit
		    || !lnchn->remote.commit)
			continue;
		log_debug_struct(lnchn->log, "our cstate: %s",
				 struct channel_state,
				 lnchn->local.commit->cstate);
		log_debug_struct(lnchn->log, "their cstate: %s",
				 struct channel_state,
				 lnchn->remote.commit->cstate);
	}
}

static struct LNchannel *find_lnchn_json(struct lightningd_state *dstate,
			      const char *buffer,
			      jsmntok_t *lnchnidtok)
{
	struct pubkey lnchnid;

	if (!pubkey_from_hexstr(buffer + lnchnidtok->start,
				lnchnidtok->end - lnchnidtok->start, &lnchnid))
		return NULL;

	return find_lnchn(dstate, &lnchnid);
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
	if (lnchn->commit_jsoncmd) {
		command_success(lnchn->commit_jsoncmd,
				null_response(lnchn->commit_jsoncmd));
		lnchn->commit_jsoncmd = NULL;
	}

	/* Have we got more changes in the meantime? */
	if (lnchn_uncommitted_changes(lnchn)) {
		log_debug(lnchn->log, "lnchn_update_complete: more changes!");
		remote_changes_pending(lnchn);
	}
}

/* FIXME: Split success and fail functions, roll state changes etc into
 * success case. */
static void lnchn_open_complete(struct LNchannel *lnchn, const char *problem)
{
	if (problem) {
		log_unusual(lnchn->log, "lnchn open failed: %s", problem);
		if (lnchn->open_jsoncmd)  {
			command_fail(lnchn->open_jsoncmd, "%s", problem);
			lnchn->open_jsoncmd = NULL;
		}
	} else {
		log_debug(lnchn->log, "lnchn open complete");
		assert(!lnchn->nc);
		/* We're connected, so record it. */
		lnchn->nc = add_connection(lnchn->dstate->rstate,
					  &lnchn->dstate->id, lnchn->id,
					  lnchn->dstate->config.fee_base,
					  lnchn->dstate->config.fee_per_satoshi,
					  lnchn->dstate->config.min_htlc_expiry,
					  lnchn->dstate->config.min_htlc_expiry);
		if (lnchn->open_jsoncmd) {
			struct json_result *response;
			response = new_json_result(lnchn->open_jsoncmd);

			json_object_start(response, NULL);
			json_add_pubkey(response, "id", lnchn->id);
			json_object_end(response);
			command_success(lnchn->open_jsoncmd, response);
			lnchn->open_jsoncmd = NULL;
		}
	}
}

static void set_lnchn_state(struct LNchannel *lnchn, enum state newstate,
			   const char *caller, bool db_commit)
{
	log_debug(lnchn->log, "%s: %s => %s", caller,
		  state_name(lnchn->state), state_name(newstate));
	lnchn->state = newstate;

	/* We can only route in normal state. */
	if (!state_is_normal(lnchn->state))
		lnchn->nc = tal_free(lnchn->nc);

	if (db_commit)
		db_update_state(lnchn);
}

static void lnchn_breakdown(struct LNchannel *lnchn)
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
	lnchn_breakdown(lnchn);
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

/* Unexpected packet received: stop listening, send error, start
 * breakdown procedure, return false. */
static bool lnchn_received_unexpected_pkt(struct LNchannel *lnchn, const Pkt *pkt,
					 const char *where)
{
	const char *p;
	Pkt *err;

	log_unusual(lnchn->log, "%s: received unexpected pkt %u (%s) in %s",
		    where, pkt->pkt_case, pkt_name(pkt->pkt_case),
		    state_name(lnchn->state));

	if (pkt->pkt_case != PKT__PKT_ERROR) {
		err = pkt_err_unexpected(lnchn, pkt);
		goto out;
	}

	/* FIXME-OLD #2:
	 *
	 * A node MUST fail the connection if it receives an `err`
	 * message, and MUST NOT send an `err` message in this case.
	 * For other connection failures, a node SHOULD send an
	 * informative `err` message.
	 */
	err = NULL;

	/* Check packet for weird chars. */
	for (p = pkt->error->problem; *p; p++) {
		if (cisprint(*p))
			continue;

		p = tal_hexstr(lnchn, pkt->error->problem,
			       strlen(pkt->error->problem));
		log_unusual(lnchn->log, "Error pkt (hex) %s", p);
		tal_free(p);
		goto out;
	}
	log_unusual(lnchn->log, "Error pkt '%s'", pkt->error->problem);

out:
	return lnchn_comms_err(lnchn, err);
}

/* Creation the bitcoin anchor tx, spending output user provided. */
static bool bitcoin_create_anchor(struct LNchannel *lnchn)
{
	struct bitcoin_tx *tx = bitcoin_tx(lnchn, 1, 1);
	size_t i;

	/* We must be offering anchor for us to try creating it */
	assert(lnchn->local.offer_anchor);

	tx->output[0].script = scriptpubkey_p2wsh(tx, lnchn->anchor.witnessscript);
	tx->output[0].amount = lnchn->anchor.input->out_amount;

	tx->input[0].txid = lnchn->anchor.input->txid;
	tx->input[0].index = lnchn->anchor.input->index;
	tx->input[0].amount = tal_dup(tx->input, u64,
				      &lnchn->anchor.input->in_amount);

	if (!wallet_add_signed_input(lnchn->dstate,
				     &lnchn->anchor.input->walletkey,
				     tx, 0))
		return false;

	bitcoin_txid(tx, &lnchn->anchor.txid);
	lnchn->anchor.tx = tx;
	lnchn->anchor.index = 0;
	/* We'll need this later, when we're told to broadcast it. */
	lnchn->anchor.satoshis = tx->output[0].amount;

	/* To avoid malleation, all inputs must be segwit! */
	for (i = 0; i < tal_count(tx->input); i++)
		assert(tx->input[i].witness);
	return true;
}

static bool open_pkt_in(struct LNchannel *lnchn, const Pkt *pkt)
{
	Pkt *err;
	struct commit_info *ci;

	assert(lnchn->state == STATE_OPEN_WAIT_FOR_OPENPKT);

	if (pkt->pkt_case != PKT__PKT_OPEN)
		return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);

	db_start_transaction(lnchn);
	ci = new_commit_info(lnchn, 0);

	err = accept_pkt_open(lnchn, pkt, &ci->revocation_hash,
			      &lnchn->remote.next_revocation_hash);
	if (err) {
		db_abort_transaction(lnchn);
		return lnchn_comms_err(lnchn, err);
	}

	db_set_visible_state(lnchn);

	/* Set up their commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	lnchn->remote.commit = ci;

	/* Witness script for anchor. */
	lnchn->anchor.witnessscript
		= bitcoin_redeem_2of2(lnchn,
				      &lnchn->local.commitkey,
				      &lnchn->remote.commitkey);

	if (lnchn->local.offer_anchor) {
		if (!bitcoin_create_anchor(lnchn)) {
			db_abort_transaction(lnchn);
			err = pkt_err(lnchn, "Own anchor unavailable");
			return lnchn_comms_err(lnchn, err);
		}
		/* FIXME: Redundant with lnchn->local.offer_anchor? */
		lnchn->anchor.ours = true;

		/* This shouldn't happen! */
		if (!setup_first_commit(lnchn)) {
			db_abort_transaction(lnchn);
			err = pkt_err(lnchn, "Own anchor has insufficient funds");
			return lnchn_comms_err(lnchn, err);
		}
		set_lnchn_state(lnchn,  STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT,
			       __func__, true);
		if (db_commit_transaction(lnchn) != NULL)
			return lnchn_database_err(lnchn);
		queue_pkt_anchor(lnchn);
		return true;
	} else {
		set_lnchn_state(lnchn,  STATE_OPEN_WAIT_FOR_ANCHORPKT,
			       __func__, true);
		if (db_commit_transaction(lnchn) != NULL)
			return lnchn_database_err(lnchn);
		return true;
	}
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

/* Dump all known channels and nodes to the lnchn. Used when a new
 * connection was established. */
static void sync_routing_table(struct lightningd_state *dstate, struct LNchannel *lnchn)
{
	struct node *n;
	struct node_map_iter it;
	int i;
	struct node_connection *nc;
	for (n = node_map_first(dstate->rstate->nodes, &it); n; n = node_map_next(dstate->rstate->nodes, &it)) {
		size_t num_edges = tal_count(n->out);
		for (i = 0; i < num_edges; i++) {
			nc = n->out[i];
			if (nc->channel_announcement)
				queue_pkt_nested(lnchn, WIRE_CHANNEL_ANNOUNCEMENT, nc->channel_announcement);
			if (nc->channel_update)
				queue_pkt_nested(lnchn, WIRE_CHANNEL_UPDATE, nc->channel_update);
		}
		if (n->node_announcement && num_edges > 0)
			queue_pkt_nested(lnchn, WIRE_NODE_ANNOUNCEMENT, n->node_announcement);
	}
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

/* Shim to handle the new packet format until we complete the
 * switch. Handing the protobuf in anyway to fall back on protobuf
 * based error handling. */
static bool nested_pkt_in(struct LNchannel *lnchn, const u32 type,
				 const u8 *innerpkt, size_t innerpktlen,
				 const Pkt *pkt)
{
	switch (type) {
	case WIRE_CHANNEL_ANNOUNCEMENT:
		handle_channel_announcement(lnchn->dstate->rstate, innerpkt, innerpktlen);
		break;
	case WIRE_CHANNEL_UPDATE:
		handle_channel_update(lnchn->dstate->rstate, innerpkt, innerpktlen);
		break;
	case WIRE_NODE_ANNOUNCEMENT:
		handle_node_announcement(lnchn->dstate->rstate, innerpkt, innerpktlen);
		break;
	default:
		/* BOLT01: Unknown even typed packets MUST kill the
		   connection, unknown odd-typed packets MAY be ignored. */
		if (type % 2 == 0){
			return lnchn_received_unexpected_pkt(lnchn, pkt, __func__);
		} else {
			log_debug(lnchn->log, "Ignoring odd typed (%d) unknown packet.", type);
			return true;
		}
	}
	return true;
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

/* Create a HTLC fulfill transaction for onchain.tx[out_num]. */
static const struct bitcoin_tx *htlc_fulfill_tx(const struct LNchannel *lnchn,
						unsigned int out_num)
{
	struct bitcoin_tx *tx = bitcoin_tx(lnchn, 1, 1);
	const struct htlc *htlc = lnchn->onchain.htlcs[out_num];
	const u8 *wscript = lnchn->onchain.wscripts[out_num];
	ecdsa_signature sig;
	u64 fee, satoshis;

	assert(htlc->r);

	tx->input[0].index = out_num;
	tx->input[0].txid = lnchn->onchain.txid;
	satoshis = htlc->msatoshi / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&lnchn->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's their HTLC, and that we collected it via rval. */
    tx->output[0].script = lnchn->final_redeemscript;/*scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
						       &lnchn->local.finalkey));*/

	log_debug(lnchn->log, "Pre-witness txlen = %zu\n",
		  measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	fee = fee_by_feerate(83 + 539 / 4, get_feerate(lnchn->dstate->topology));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust(satoshis - fee))
		fatal("HTLC fulfill amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	lnchn_sign_htlc_fulfill(lnchn, tx, wscript, &sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx,
						    htlc->r, &sig, wscript);

	log_debug(lnchn->log, "tx cost for htlc fulfill tx: %zu",
		  measure_tx_cost(tx));

	return tx;
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

/* FIXME-OLD #onchain:
 *
 * If the node receives... a redemption preimage for an unresolved *commitment
 * tx* output it was offered, it MUST *resolve* the output by spending it using
 * the preimage.
 */
static bool fulfill_onchain(struct LNchannel *lnchn, struct htlc *htlc)
{
	size_t i;

	for (i = 0; i < tal_count(lnchn->onchain.htlcs); i++) {
		if (lnchn->onchain.htlcs[i] == htlc) {
			/* Already irrevocably resolved? */
			if (lnchn->onchain.resolved[i])
				return false;
			lnchn->onchain.resolved[i]
				= htlc_fulfill_tx(lnchn, i);
			broadcast_tx(lnchn->dstate->topology,
				     lnchn, lnchn->onchain.resolved[i], NULL);
			return true;
		}
	}
	fatal("Unknown HTLC to fulfill onchain");
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

static struct io_plan *pkt_out(struct io_conn *conn, struct LNchannel *lnchn)
{
	Pkt *out;
	size_t n = tal_count(lnchn->outpkt);

	if (n == 0) {
		/* We close the connection once we've sent everything. */
		if (!state_can_io(lnchn->state)) {
			log_debug(lnchn->log, "pkt_out: no IO possible, closing");
			return io_close(conn);
		}
		return io_out_wait(conn, lnchn, pkt_out, lnchn);
	}

	if (lnchn->fake_close || !lnchn->output_enabled)
		return io_out_wait(conn, lnchn, pkt_out, lnchn);

	out = lnchn->outpkt[0];
	memmove(lnchn->outpkt, lnchn->outpkt + 1, (sizeof(*lnchn->outpkt)*(n-1)));
	tal_resize(&lnchn->outpkt, n-1);
	log_debug(lnchn->log, "pkt_out: writing %s", pkt_name(out->pkt_case));
	return lnchn_write_packet(conn, lnchn, out, pkt_out);
}

static void clear_output_queue(struct LNchannel *lnchn)
{
	size_t i, n = tal_count(lnchn->outpkt);
	for (i = 0; i < n; i++)
		tal_free(lnchn->outpkt[i]);
	tal_resize(&lnchn->outpkt, 0);
}

static struct io_plan *pkt_in(struct io_conn *conn, struct LNchannel *lnchn)
{
	bool keep_going = true;

	/* We ignore packets if they tell us to, or we're closing already */
	if (lnchn->fake_close || !state_can_io(lnchn->state))
		keep_going = true;

	/* Sidestep the state machine for nested packets */
	else if (lnchn->inpkt->pkt_case == PKT__PKT_NESTED)
		keep_going = nested_pkt_in(lnchn, lnchn->inpkt->nested->type,
					   lnchn->inpkt->nested->inner_pkt.data,
					   lnchn->inpkt->nested->inner_pkt.len,
					   lnchn->inpkt);
	else if (state_is_normal(lnchn->state))
		keep_going = normal_pkt_in(lnchn, lnchn->inpkt);
	else if (state_is_shutdown(lnchn->state))
		keep_going = shutdown_pkt_in(lnchn, lnchn->inpkt);
	else if (lnchn->state == STATE_MUTUAL_CLOSING)
		keep_going = closing_pkt_in(lnchn, lnchn->inpkt);
	else if (lnchn->state == STATE_OPEN_WAIT_FOR_OPENPKT)
		keep_going = open_pkt_in(lnchn, lnchn->inpkt);
	else if (lnchn->state == STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT)
		keep_going = open_ouranchor_pkt_in(lnchn, lnchn->inpkt);
	else if (lnchn->state == STATE_OPEN_WAIT_FOR_ANCHORPKT)
		keep_going = open_theiranchor_pkt_in(lnchn, lnchn->inpkt);
	else if (state_is_openwait(lnchn->state))
		keep_going = open_wait_pkt_in(lnchn, lnchn->inpkt);
	else {
		log_unusual(lnchn->log,
			    "Unexpected state %s", state_name(lnchn->state));
		keep_going = false;
	}

	lnchn->inpkt = tal_free(lnchn->inpkt);
	if (keep_going)
		return lnchn_read_packet(conn, lnchn, pkt_in);
	else
		return lnchn_close(conn, lnchn);
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

static struct io_plan *init_pkt_in(struct io_conn *conn, struct LNchannel *lnchn)
{
	if (lnchn->inpkt->pkt_case != PKT__PKT_INIT) {
		lnchn_received_unexpected_pkt(lnchn, lnchn->inpkt, __func__);
		goto fail;
	}

	/* They might have missed the error, tell them before hanging up */
	if (state_is_error(lnchn->state)) {
		queue_pkt_err(lnchn, pkt_err(lnchn, "In error state %s",
					    state_name(lnchn->state)));
		goto fail;
	}

	/* We might have had an onchain event while handshaking! */
	if (!state_can_io(lnchn->state))
		goto fail;

	if (lnchn->inpkt->init->has_features) {
		size_t i;

		/* FIXME-OLD #2:
		 *
		 * The receiving node SHOULD ignore any odd feature bits it
		 * does not support, and MUST fail the connection if any
		 * unsupported even `features` bit is set. */
		for (i = 0; i < lnchn->inpkt->init->features.len*CHAR_BIT; i++) {
			size_t byte = i / CHAR_BIT, bit = i % CHAR_BIT;
			if (lnchn->inpkt->init->features.data[byte] & (1<<bit)) {
				/* Can't handle even features. */
				if (i % 2 != 0) {
					log_debug(lnchn->log,
						  "They offered feature %zu", i);
					continue;
				}
				queue_pkt_err(lnchn,
					      pkt_err(lnchn,
						      "Unsupported feature %zu",
						      i));
				goto fail;
			}
		}
	}

	/* Send any packets they missed. */
	retransmit_pkts(lnchn, lnchn->inpkt->init->ack);

	/* We let the conversation go this far in case they missed the
	 * close packets.  But now we can close if we're done. */
	if (!state_can_io(lnchn->state)) {
		log_debug(lnchn->log, "State %s, closing immediately",
			  state_name(lnchn->state));
		goto fail;
	}

	/* Back into normal mode. */
	lnchn->inpkt = tal_free(lnchn->inpkt);

	lnchn_has_connected(lnchn);

	if (state_is_normal(lnchn->state)){
		announce_channel(lnchn->dstate, lnchn);
		sync_routing_table(lnchn->dstate, lnchn);
	}

	return io_duplex(conn,
			 lnchn_read_packet(conn, lnchn, pkt_in),
			 pkt_out(conn, lnchn));

fail:
	/* We always free inpkt; they may yet reconnect. */
	lnchn->inpkt = tal_free(lnchn->inpkt);
	return pkt_out(conn, lnchn);
}

static struct io_plan *read_init_pkt(struct io_conn *conn,
					  struct LNchannel *lnchn)
{
	return lnchn_read_packet(conn, lnchn, init_pkt_in);
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

/* Crypto is on, we are live. */
static struct io_plan *lnchn_crypto_on(struct io_conn *conn, struct LNchannel *lnchn)
{
    struct bitcoin_address redeem_addr;

	lnchn_secrets_init(lnchn);

    /*init redeem script before save lnchn into db and after the secret is done*/
    if (select_wallet_address_bystr(lnchn->dstate, &redeem_addr))
        lnchn->final_redeemscript = /*now only use p2pkh script*/
            gen_redeemscript_from_wallet_str(lnchn, &redeem_addr, 0);
    else
        lnchn->final_redeemscript = scriptpubkey_p2sh(lnchn, 
            bitcoin_redeem_single(lnchn, &lnchn->local.finalkey));

    log_debug(lnchn->log, "set redeem script as {%s}", 
        tal_hexstr(lnchn, lnchn->final_redeemscript, tal_count(lnchn->final_redeemscript)));

	lnchn_get_revocation_hash(lnchn, 0, &lnchn->local.next_revocation_hash);

	assert(lnchn->state == STATE_INIT);

	/* Counter is 1 for sending pkt_open: we'll do it in retransmit_pkts */
	lnchn->order_counter++;

	db_start_transaction(lnchn);
	set_lnchn_state(lnchn, STATE_OPEN_WAIT_FOR_OPENPKT, __func__, true);

	/* FIXME: Start timeout, and close lnchn if they don't progress! */
	db_create_lnchn(lnchn);
	if (db_commit_transaction(lnchn) != NULL) {
		lnchn_database_err(lnchn);
		return lnchn_close(conn, lnchn);
	}

	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	lnchn->local.commit = new_commit_info(lnchn, 0);
	lnchn->local.commit->revocation_hash = lnchn->local.next_revocation_hash;
	lnchn_get_revocation_hash(lnchn, 1, &lnchn->local.next_revocation_hash);

	return lnchn_send_init(conn,lnchn);
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
		      struct log *log,
		      enum state state,
		      bool offer_anchor)
{
	struct LNchannel *lnchn = tal(dstate, struct LNchannel);

	lnchn->state = state;
	lnchn->connected = false;
	lnchn->id = NULL;
	lnchn->dstate = dstate;
	lnchn->io_data = NULL;
    lnchn->final_redeemscript = NULL;
	lnchn->secrets = NULL;
	list_head_init(&lnchn->watches);
	lnchn->inpkt = NULL;
	lnchn->outpkt = tal_arr(lnchn, Pkt *, 0);
	lnchn->open_jsoncmd = NULL;
	lnchn->commit_jsoncmd = NULL;
	list_head_init(&lnchn->their_commits);
	lnchn->anchor.ok_depth = -1;
	lnchn->order_counter = 0;
	lnchn->their_commitsigs = 0;
	lnchn->cur_commit.watch = NULL;
	lnchn->closing.their_sig = NULL;
	lnchn->closing.our_script = NULL;
	lnchn->closing.their_script = NULL;
	lnchn->closing.shutdown_order = (s64)-1LL;
	lnchn->closing.closing_order = (s64)-1LL;
	lnchn->closing.sigs_in = 0;
	lnchn->onchain.tx = NULL;
	lnchn->onchain.resolved = NULL;
	lnchn->onchain.htlcs = NULL;
	lnchn->onchain.wscripts = NULL;
	lnchn->commit_timer = NULL;
	lnchn->nc = NULL;
	lnchn->their_prev_revocation_hash = NULL;
	lnchn->conn = NULL;
	lnchn->fake_close = false;
	lnchn->output_enabled = true;
	lnchn->local.offer_anchor = offer_anchor;
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

	list_add(&dstate->lnchns, &lnchn->list);
	tal_add_destructor(lnchn, destroy_lnchn);
	return lnchn;
}

static struct LNchannel_address *find_address(struct lightningd_state *dstate,
					 const struct pubkey *id)
{
	struct LNchannel_address *i;

	list_for_each(&dstate->addresses, i, list) {
		if (structeq(&id->pubkey, &i->id.pubkey))
			return i;
	}
	return NULL;
}

static bool add_lnchn_address(struct lightningd_state *dstate,
			     const struct pubkey *id,
			     const struct netaddr *addr)
{
	struct LNchannel_address *a = find_address(dstate, id);
	if (a) {
		a->addr = *addr;
	} else {
		a = tal(dstate, struct LNchannel_address);
		a->addr = *addr;
		a->id = *id;
		list_add_tail(&dstate->addresses, &a->list);
	}
	return db_add_lnchn_address(dstate, a);
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
			   u32 expiry,
			   enum htlc_state state)
{
	struct htlc *h = tal(lnchn, struct htlc);
	h->state = state;
	h->msatoshi = msatoshi;
	h->rhash = *rhash;
	h->r = NULL;
	h->fail = NULL;
	if (!blocks_to_abs_locktime(expiry, &h->expiry))
		fatal("Invalid HTLC expiry %u", expiry);
	if (htlc_owner(h) == LOCAL) {
		if (src) {
			h->deadline = abs_locktime_to_blocks(&src->expiry)
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

static int make_listen_fd(struct lightningd_state *dstate,
			  int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(dstate->base_log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			log_unusual(dstate->base_log,
				    "Failed setting socket reuse: %s",
				    strerror(errno));

		if (bind(fd, addr, len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed to bind on %u socket: %s",
				    domain, strerror(errno));
			goto fail;
		}
	}

	if (listen(fd, 5) != 0) {
		log_unusual(dstate->base_log,
			    "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
		goto fail;
	}
	return fd;

fail:
	close_noerr(fd);
	return -1;
}

void setup_listeners(struct lightningd_state *dstate)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;

	if (!dstate->portnum)
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(dstate->portnum);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(dstate->portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(dstate, AF_INET6, &addr6, sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
		} else {
			addr.sin_port = in6.sin6_port;
			assert(dstate->portnum == ntohs(addr.sin_port));
			log_debug(dstate->base_log,
				  "Creating IPv6 listener on port %u",
				  dstate->portnum);
			io_new_listener(dstate, fd1, lnchn_connected_in, dstate);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(dstate, AF_INET, &addr, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(dstate->base_log,
				    "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
		} else {
			assert(dstate->portnum == ntohs(addr.sin_port));
			log_debug(dstate->base_log,
				  "Creating IPv4 listener on port %u",
				  dstate->portnum);
			io_new_listener(dstate, fd2, lnchn_connected_in, dstate);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address");
}

static void lnchn_failed(struct lightningd_state *dstate,
			struct json_connecting *connect)
{
	/* FIXME: Better diagnostics! */
	command_fail(connect->cmd, "Failed to connect to lnchn %s:%s",
		     connect->name, connect->port);
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

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port} using hex-encoded {tx} to fund",
	"Returns the {id} on success (once channel established)"
};
AUTODATA(json_command, &connect_command);

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

static bool outputscript_eq(const struct bitcoin_tx_output *out,
			    size_t i, const u8 *script)
{
	if (tal_count(out[i].script) != tal_count(script))
		return false;
	return memcmp(out[i].script, script, tal_count(script)) == 0;
}

/* This tx is their commitment;
 * fill in onchain.htlcs[], wscripts[], to_us_idx and to_them_idx */
static bool map_onchain_outputs(struct LNchannel *lnchn,
				const struct sha256 *rhash,
				const struct bitcoin_tx *tx,
				enum side side,
				unsigned int commit_num)
{
	u8 *to_us, *to_them, *to_them_wscript, *to_us_wscript;
	struct htlc_output_map *hmap;
	size_t i;

	lnchn->onchain.to_us_idx = lnchn->onchain.to_them_idx = -1;
	lnchn->onchain.htlcs = tal_arr(tx, struct htlc *, tal_count(tx->output));
	lnchn->onchain.wscripts = tal_arr(tx, const u8 *, tal_count(tx->output));

	to_us = commit_output_to_us(tx, lnchn, rhash, side, &to_us_wscript);
	to_them = commit_output_to_them(tx, lnchn, rhash, side,
					&to_them_wscript);

	/* Now generate the wscript hashes for every possible HTLC. */
	hmap = get_htlc_output_map(tx, lnchn, rhash, side, commit_num);

	for (i = 0; i < tal_count(tx->output); i++) {
		log_debug(lnchn->log, "%s: output %zi", __func__, i);
		if (lnchn->onchain.to_us_idx == -1
		    && outputscript_eq(tx->output, i, to_us)) {
			log_add(lnchn->log, " -> to us");
			lnchn->onchain.htlcs[i] = NULL;
			lnchn->onchain.wscripts[i] = to_us_wscript;
			lnchn->onchain.to_us_idx = i;
			continue;
		}
		if (lnchn->onchain.to_them_idx == -1
		    && outputscript_eq(tx->output, i, to_them)) {
			log_add(lnchn->log, " -> to them");
			lnchn->onchain.htlcs[i] = NULL;
			lnchn->onchain.wscripts[i] = to_them_wscript;
			lnchn->onchain.to_them_idx = i;
			continue;
		}
		/* Must be an HTLC output */
		lnchn->onchain.htlcs[i] = txout_get_htlc(hmap,
					  tx->output[i].script,
					  lnchn->onchain.wscripts+i);
		if (!lnchn->onchain.htlcs[i]) {
			log_add(lnchn->log, "no HTLC found");
			goto fail;
		}
		tal_steal(lnchn->onchain.htlcs, lnchn->onchain.htlcs[i]);
		tal_steal(lnchn->onchain.wscripts, lnchn->onchain.wscripts[i]);
		log_add(lnchn->log, "HTLC %"PRIu64, lnchn->onchain.htlcs[i]->id);
	}
	tal_free(hmap);
	return true;

fail:
	tal_free(hmap);
	return false;
}

static bool is_mutual_close(const struct LNchannel *lnchn,
			    const struct bitcoin_tx *tx)
{
	const u8 *ours, *theirs;

	ours = lnchn->closing.our_script;
	theirs = lnchn->closing.their_script;
	/* If we don't know the closing scripts, can't have signed them. */
	if (!ours || !theirs)
		return false;

	if (tal_count(tx->output) != 2)
		return false;

	/* Without knowing fee amounts, can't determine order.  Check both. */
	if (scripteq(tx->output[0].script, ours)
	    && scripteq(tx->output[1].script, theirs))
		return true;

	if (scripteq(tx->output[0].script, theirs)
	    && scripteq(tx->output[1].script, ours))
		return true;

	return false;
}

/* Create a HTLC refund collection for onchain.tx output out_num. */
static const struct bitcoin_tx *htlc_timeout_tx(const struct LNchannel *lnchn,
						unsigned int out_num)
{
	const struct htlc *htlc = lnchn->onchain.htlcs[out_num];
	const u8 *wscript = lnchn->onchain.wscripts[out_num];
	struct bitcoin_tx *tx = bitcoin_tx(lnchn, 1, 1);
	ecdsa_signature sig;
	u64 fee, satoshis;

	/* We must set locktime so HTLC expiry can OP_CHECKLOCKTIMEVERIFY */
	tx->lock_time = htlc->expiry.locktime;
	tx->input[0].index = out_num;
	tx->input[0].txid = lnchn->onchain.txid;
	satoshis = htlc->msatoshi / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&lnchn->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's our HTLC, and that we collected it via timeout. */
    tx->output[0].script = lnchn->final_redeemscript;/*scriptpubkey_p2sh(tx,
				 bitcoin_redeem_single(tx,
						       &lnchn->local.finalkey));*/

	log_unusual(lnchn->log, "Pre-witness txlen = %zu\n",
		    measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	fee = fee_by_feerate(83 + 539 / 4, get_feerate(lnchn->dstate->topology));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust(satoshis - fee))
		fatal("HTLC refund amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	lnchn_sign_htlc_refund(lnchn, tx, wscript, &sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx,
						    NULL, &sig, wscript);

	log_unusual(lnchn->log, "tx cost for htlc timeout tx: %zu",
		    measure_tx_cost(tx));

	return tx;
}

static void reset_onchain_closing(struct LNchannel *lnchn)
{
	if (lnchn->onchain.tx) {
		log_unusual_struct(lnchn->log,
				   "New anchor spend, forgetting old tx %s",
				   struct sha256_double, &lnchn->onchain.txid);
		lnchn->onchain.tx = tal_free(lnchn->onchain.tx);
		lnchn->onchain.resolved = NULL;
		lnchn->onchain.htlcs = NULL;
		lnchn->onchain.wscripts = NULL;
	}
}

static const struct bitcoin_tx *irrevocably_resolved(struct LNchannel *lnchn)
{
	/* We can't all be irrevocably resolved until the commit tx is,
	 * so just mark that as resolving us. */
	return lnchn->onchain.tx;
}

/* We usually don't fail HTLCs we offered, but if the lnchn breaks down
 * before we've confirmed it, this is exactly what happens. */
static void fail_own_htlc(struct LNchannel *lnchn, struct htlc *htlc)
{
	/* We can't do anything about db failures; lnchn already closed. */
	db_start_transaction(lnchn);
	set_htlc_fail(lnchn, htlc, "lnchn closed", strlen("lnchn closed"));
	our_htlc_failed(lnchn, htlc);
	db_commit_transaction(lnchn);
}

/* We've spent an HTLC output to get our funds back.  There's still a
 * chance that they could also spend the HTLC output (using the preimage),
 * so we need to wait for some confirms.
 *
 * However, we don't want to wait too long: our upstream will get upset if
 * their HTLC has timed out and we don't close it.  So we wait one less
 * than the HTLC timeout difference.
 */
static enum watch_result our_htlc_timeout_depth(struct LNchannel *lnchn,
						unsigned int depth,
						const struct sha256_double *txid,
						struct htlc *htlc)
{
	if (depth == 0)
		return KEEP_WATCHING;
	if (depth + 1 < lnchn->dstate->config.min_htlc_expiry)
		return KEEP_WATCHING;
	fail_own_htlc(lnchn, htlc);
	return DELETE_WATCH;
}

static enum watch_result our_htlc_depth(struct LNchannel *lnchn,
					unsigned int depth,
					const struct sha256_double *txid,
					enum side whose_commit,
					unsigned int out_num)
{
	struct htlc *h = lnchn->onchain.htlcs[out_num];
	u32 height;

	/* Must be in a block. */
	if (depth == 0)
		return KEEP_WATCHING;

	height = get_block_height(lnchn->dstate->topology);

	/* FIXME-OLD #onchain:
	 *
	 * If the *commitment tx* is the other node's, the output is
	 * considered *timed out* once the HTLC is expired.  If the
	 * *commitment tx* is this node's, the output is considered *timed
	 * out* once the HTLC is expired, AND the output's
	 * `OP_CHECKSEQUENCEVERIFY` delay has passed.
	 */
	if (height < abs_locktime_to_blocks(&h->expiry))
		return KEEP_WATCHING;

	if (whose_commit == LOCAL) {
		if (depth < rel_locktime_to_blocks(&lnchn->remote.locktime))
			return KEEP_WATCHING;
	}

	/* FIXME-OLD #onchain:
	 *
	 * If the output has *timed out* and not been *resolved*, the node
	 * MUST *resolve* the output by spending it.
	 */
	/* FIXME: we should simply delete this watch if HTLC is fulfilled. */
	if (!lnchn->onchain.resolved[out_num]) {
		lnchn->onchain.resolved[out_num]	= htlc_timeout_tx(lnchn, out_num);
		watch_tx(lnchn->onchain.resolved[out_num],
			 lnchn->dstate->topology,
			 lnchn,
			 lnchn->onchain.resolved[out_num],
			 our_htlc_timeout_depth, h);
		broadcast_tx(lnchn->dstate->topology,
			     lnchn, lnchn->onchain.resolved[out_num], NULL);
	}
	return DELETE_WATCH;
}

static enum watch_result our_htlc_depth_theircommit(struct LNchannel *lnchn,
						    unsigned int depth,
						    const struct sha256_double *txid,
						    ptrint_t *out_num)
{
	return our_htlc_depth(lnchn, depth, txid, REMOTE, ptr2int(out_num));
}

static enum watch_result our_htlc_depth_ourcommit(struct LNchannel *lnchn,
						  unsigned int depth,
						  const struct sha256_double *txid,
						  ptrint_t *out_num)
{
	return our_htlc_depth(lnchn, depth, txid, LOCAL, ptr2int(out_num));
}

static enum watch_result their_htlc_depth(struct LNchannel *lnchn,
					  unsigned int depth,
					  const struct sha256_double *txid,
					  ptrint_t *out_num)
{
	u32 height;
	const struct htlc *htlc = lnchn->onchain.htlcs[ptr2int(out_num)];

	/* Must be in a block. */
	if (depth == 0)
		return KEEP_WATCHING;

	height = get_block_height(lnchn->dstate->topology);

	/* FIXME-OLD #onchain:
	 *
	 * Otherwise, if the output HTLC has expired, it is considered
	 * *irrevocably resolved*.
	 */
	if (height < abs_locktime_to_blocks(&htlc->expiry))
		return KEEP_WATCHING;

	lnchn->onchain.resolved[ptr2int(out_num)] = irrevocably_resolved(lnchn);
	return DELETE_WATCH;
}

static enum watch_result our_main_output_depth(struct LNchannel *lnchn,
					       unsigned int depth,
					       const struct sha256_double *txid,
					       void *unused)
{
	/* Not past CSV timeout? */
	if (depth < rel_locktime_to_blocks(&lnchn->remote.locktime))
		return KEEP_WATCHING;

	assert(lnchn->onchain.to_us_idx != -1);

	/* FIXME-OLD #onchain:
	 *
	 * 1. _A's main output_: A node SHOULD spend this output to a
	 *    convenient address.  This avoids having to remember the
	 *    complicated witness script associated with that particular
	 *    channel for later spending. ... If the output is spent (as
	 *    recommended), the output is *resolved* by the spending
	 *    transaction
	 */
	lnchn->onchain.resolved[lnchn->onchain.to_us_idx]
		= bitcoin_spend_ours(lnchn);
	broadcast_tx(lnchn->dstate->topology,
		     lnchn, lnchn->onchain.resolved[lnchn->onchain.to_us_idx],
		     NULL);
	return DELETE_WATCH;
}

/* Any of our HTLCs we didn't have in our commitment tx, but they did,
 * we can't fail until we're sure our commitment tx will win. */
static enum watch_result our_unilateral_depth(struct LNchannel *lnchn,
					      unsigned int depth,
					      const struct sha256_double *txid,
					      void *unused)
{
	struct htlc_map_iter it;
	struct htlc *h;

	if (depth < lnchn->dstate->config.min_htlc_expiry)
		return KEEP_WATCHING;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (htlc_owner(h) == LOCAL
		    && !htlc_has(h, HTLC_LOCAL_F_COMMITTED)
		    && htlc_has(h, HTLC_REMOTE_F_COMMITTED)) {
			log_debug(lnchn->log,
				  "%s:failing uncommitted htlc %"PRIu64,
				  __func__, h->id);
			fail_own_htlc(lnchn, h);
		}
	}
	return DELETE_WATCH;
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

static void resolve_our_htlc(struct LNchannel *lnchn,
			     unsigned int out_num,
			     enum watch_result (*cb)(struct LNchannel *lnchn,
						     unsigned int depth,
						     const struct sha256_double*,
						     ptrint_t *out_num))
{
	/* FIXME-OLD #onchain:
	 *
	 * A node MUST watch for spends of *commitment tx* outputs for HTLCs
	 * it offered; each one must be *resolved* by a timeout transaction
	 * (the node pays back to itself) or redemption transaction (the other
	 * node provides the redemption preimage).
	 */
	watch_txo(lnchn->onchain.tx,
		  lnchn->dstate->topology,
		  lnchn, &lnchn->onchain.txid, out_num,
		  our_htlc_spent, lnchn->onchain.htlcs[out_num]);
	watch_txid(lnchn->onchain.tx,
		   lnchn->dstate->topology,
		   lnchn, &lnchn->onchain.txid, cb, int2ptr(out_num));
}

static void resolve_their_htlc(struct LNchannel *lnchn, unsigned int out_num)
{
	/* FIXME-OLD #onchain:
	 *
	 * If the node ... already knows... a redemption preimage for an
	 * unresolved *commitment tx* output it was offered, it MUST *resolve*
	 * the output by spending it using the preimage.
	 */
	if (lnchn->onchain.htlcs[out_num]->r) {
		lnchn->onchain.resolved[out_num]	= htlc_fulfill_tx(lnchn, out_num);
		broadcast_tx(lnchn->dstate->topology,
			     lnchn, lnchn->onchain.resolved[out_num], NULL);
	} else {
		/* FIXME-OLD #onchain:
		 *
		 * Otherwise, if the output HTLC has expired, it is considered
		 * *irrevocably resolved*.
		 */
		watch_tx(lnchn->onchain.tx,
			 lnchn->dstate->topology,
			 lnchn, lnchn->onchain.tx,
			 their_htlc_depth, int2ptr(out_num));
	}
}

/* FIXME-OLD #onchain:
 *
 * When node A sees its own *commitment tx*:
 */
static void resolve_our_unilateral(struct LNchannel *lnchn)
{
	unsigned int i;
	struct chain_topology *topo = lnchn->dstate->topology;
	const struct bitcoin_tx *tx = lnchn->onchain.tx;

	/* This only works because we always watch for a long time before
	 * freeing lnchn, by which time this has resolved.  We could create
	 * resolved[] entries for these uncommitted HTLCs, too. */
	watch_tx(tx, topo, lnchn, tx, our_unilateral_depth, NULL);

	for (i = 0; i < tal_count(tx->output); i++) {
		/* FIXME-OLD #onchain:
		 *
		 * 1. _A's main output_: A node SHOULD spend this output to a
		 *    convenient address. ... A node MUST wait until the
		 *    `OP_CHECKSEQUENCEVERIFY` delay has passed (as specified
		 *    by the other node's `open_channel` `delay` field) before
		 *    spending the output.
		 */
		if (i == lnchn->onchain.to_us_idx)
			watch_tx(tx, topo,
				 lnchn, tx, our_main_output_depth, NULL);

		/* FIXME-OLD #onchain:
		 *
		 * 2. _B's main output_: No action required, this output is
		 *    considered *resolved* by the *commitment tx*.
		 */
		else if (i == lnchn->onchain.to_them_idx)
			lnchn->onchain.resolved[i] = tx;

		/* FIXME-OLD #onchain:
		 *
		 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our
		 *    Offers below.
		 */
		else if (htlc_owner(lnchn->onchain.htlcs[i]) == LOCAL)
			resolve_our_htlc(lnchn, i, our_htlc_depth_ourcommit);

		/* FIXME-OLD #onchain:
		 *
		 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
		 *    Offers below.
		 */
		else
			resolve_their_htlc(lnchn, i);
	}
}

/* FIXME-OLD #onchain:
 *
 * Similarly, when node A sees a *commitment tx* from B:
 */
static void resolve_their_unilateral(struct LNchannel *lnchn)
{
	unsigned int i;
	const struct bitcoin_tx *tx = lnchn->onchain.tx;

	for (i = 0; i < tal_count(tx->output); i++) {
		/* FIXME-OLD #onchain:
		 *
		 * 1. _A's main output_: No action is required; this is a
		 *    simple P2WPKH output.  This output is considered
		 *    *resolved* by the *commitment tx*.
		 */
		if (i == lnchn->onchain.to_us_idx)
			lnchn->onchain.resolved[i] = tx;
		/* FIXME-OLD #onchain:
		 *
		 * 2. _B's main output_: No action required, this output is
		 *    considered *resolved* by the *commitment tx*.
		 */
		else if (i == lnchn->onchain.to_them_idx)
			lnchn->onchain.resolved[i] = tx;
		/* FIXME-OLD #onchain:
		 *
		 * 3. _A's offered HTLCs_: See On-chain HTLC Handling: Our
		 * Offers below.
		 */
		else if (htlc_owner(lnchn->onchain.htlcs[i]) == LOCAL)
			resolve_our_htlc(lnchn, i, our_htlc_depth_theircommit);
		/*
		 * 4. _B's offered HTLCs_: See On-chain HTLC Handling: Their
		 * Offers below.
		 */
		else
			resolve_their_htlc(lnchn, i);
	}
}

static void resolve_mutual_close(struct LNchannel *lnchn)
{
	unsigned int i;

	/* FIXME-OLD #onchain:
	 *
	 * A node doesn't need to do anything else as it has already agreed to
	 * the output, which is sent to its specified scriptpubkey (see FIXME-OLD
	 * #2 "4.1: Closing initiation: close_shutdown").
	 */
	for (i = 0; i < tal_count(lnchn->onchain.tx->output); i++)
		lnchn->onchain.resolved[i] = irrevocably_resolved(lnchn);

	/* No HTLCs. */
	lnchn->onchain.htlcs = tal_arrz(lnchn->onchain.tx,
				       struct htlc *,
				       tal_count(lnchn->onchain.tx->output));
}

/* Called every time the tx spending the funding tx changes depth. */
static enum watch_result check_for_resolution(struct LNchannel *lnchn,
					      unsigned int depth,
					      const struct sha256_double *txid,
					      void *unused)
{
	size_t i, n = tal_count(lnchn->onchain.resolved);
	size_t forever = lnchn->dstate->config.forever_confirms;

	/* FIXME-OLD #onchain:
	 *
	 * A node MUST *resolve* all outputs as specified below, and MUST be
	 * prepared to resolve them multiple times in case of blockchain
	 * reorganizations.
	 */
	for (i = 0; i < n; i++)
		if (!lnchn->onchain.resolved[i])
			return KEEP_WATCHING;

	/* FIXME-OLD #onchain:
	 *
	 * Outputs which are *resolved* by a transaction are considered
	 * *irrevocably resolved* once they are included in a block at least
	 * 100 deep on the most-work blockchain.
	 */
	if (depth < forever)
		return KEEP_WATCHING;

	for (i = 0; i < n; i++) {
		struct sha256_double txid;

		bitcoin_txid(lnchn->onchain.resolved[i], &txid);
		if (get_tx_depth(lnchn->dstate->topology, &txid) < forever)
			return KEEP_WATCHING;
	}

	/* FIXME-OLD #onchain:
	 *
	 * A node MUST monitor the blockchain for transactions which spend any
	 * output which is not *irrevocably resolved* until all outputs are
	 * *irrevocably resolved*.
	 */
	set_lnchn_state(lnchn, STATE_CLOSED, "check_for_resolution", false);
	db_forget_lnchn(lnchn);

	/* It's theoretically possible that lnchn is still writing output */
	if (!lnchn->conn)
		io_break(lnchn);
	else
		io_wake(lnchn);

	return DELETE_WATCH;
}

static bool find_their_old_tx(struct LNchannel *lnchn,
			      const struct sha256_double *txid,
			      u64 *idx)
{
	/* FIXME: Don't keep these in memory, search db here. */
	struct their_commit *tc;

	log_debug_struct(lnchn->log, "Finding txid %s", struct sha256_double,
			 txid);
	list_for_each(&lnchn->their_commits, tc, list) {
		if (structeq(&tc->txid, txid)) {
			*idx = tc->commit_num;
			return true;
		}
	}
	return false;
}

static void resolve_their_steal(struct LNchannel *lnchn,
				const struct sha256 *revocation_preimage)
{
	int i, n;
	const struct bitcoin_tx *tx = lnchn->onchain.tx;
	struct bitcoin_tx *steal_tx;
	size_t wsize = 0;
	u64 input_total = 0, fee;

	/* Create steal_tx: don't need to steal to_us output */
	if (lnchn->onchain.to_us_idx == -1)
		steal_tx = bitcoin_tx(tx, tal_count(tx->output), 1);
	else
		steal_tx = bitcoin_tx(tx, tal_count(tx->output) - 1, 1);
	n = 0;

	log_debug(lnchn->log, "Analyzing tx to steal:");
	for (i = 0; i < tal_count(tx->output); i++) {
		/* FIXME-OLD #onchain:
		 * 1. _A's main output_: No action is required; this is a
		 *    simple P2WPKH output.  This output is considered
		 *    *resolved* by the *commitment tx*.
		 */
		if (i == lnchn->onchain.to_us_idx) {
			log_debug(lnchn->log, "%i is to-us, ignoring", i);
			lnchn->onchain.resolved[i] = tx;
			continue;
		}

		/* FIXME-OLD #onchain:
		 *
		 * 2. _B's main output_: The node MUST *resolve* this by
		 * spending using the revocation preimage.
		 *
		 * 3. _A's offered HTLCs_: The node MUST *resolve* this by
		 * spending using the revocation preimage.
		 *
		 * 4. _B's offered HTLCs_: The node MUST *resolve* this by
		 * spending using the revocation preimage.
		 */
		lnchn->onchain.resolved[i] = steal_tx;

		/* Connect it up. */
		steal_tx->input[n].txid = lnchn->onchain.txid;
		steal_tx->input[n].index = i;
		steal_tx->input[n].amount = tal_dup(steal_tx, u64,
						    &tx->output[i].amount);
		/* Track witness size, for fee. */
		wsize += tal_count(lnchn->onchain.wscripts[i]);
		input_total += tx->output[i].amount;
		n++;
	}
	assert(n == tal_count(steal_tx->input));

	fee = get_feerate(lnchn->dstate->topology)
		* (measure_tx_cost(steal_tx) + wsize) / 1000;

	if (fee > input_total || is_dust(input_total - fee)) {
		log_unusual(lnchn->log, "Not worth stealing tiny amount %"PRIu64,
			    input_total);
		/* Consider them all resolved by steal tx. */
		for (i = 0; i < tal_count(lnchn->onchain.resolved); i++)
			lnchn->onchain.resolved[i] = tx;
		tal_free(steal_tx);
		return;
	}
	steal_tx->output[0].amount = input_total - fee;
    steal_tx->output[0].script = lnchn->final_redeemscript;/* scriptpubkey_p2sh(steal_tx,
				 bitcoin_redeem_single(steal_tx,
						       &lnchn->local.finalkey));*/

	/* Now, we can sign them all (they're all of same form). */
	n = 0;
	for (i = 0; i < tal_count(tx->output); i++) {
		ecdsa_signature sig;

		/* Don't bother stealing the output already to us. */
		if (i == lnchn->onchain.to_us_idx)
			continue;

		lnchn_sign_steal_input(lnchn, steal_tx, n,
				      lnchn->onchain.wscripts[i],
				      &sig);

		steal_tx->input[n].witness
			= bitcoin_witness_secret(steal_tx,
						 revocation_preimage,
						 sizeof(*revocation_preimage),
						 &sig,
						 lnchn->onchain.wscripts[i]);
		n++;
	}
	assert(n == tal_count(steal_tx->input));

	broadcast_tx(lnchn->dstate->topology, lnchn, steal_tx, NULL);
}

static struct sha256 *get_rhash(struct LNchannel *lnchn, u64 commit_num,
				struct sha256 *rhash)
{
	struct sha256 preimage;

	/* Previous revoked tx? */
	if (shachain_get_hash(&lnchn->their_preimages,
			      0xFFFFFFFFFFFFFFFFL - commit_num,
			      &preimage)) {
		sha256(rhash, &preimage, sizeof(preimage));
		return tal_dup(lnchn, struct sha256, &preimage);
	}

	/* Current tx? */
	if (commit_num == lnchn->remote.commit->commit_num) {
		*rhash = lnchn->remote.commit->revocation_hash;
		return NULL;
	}

	/* Last tx, but we haven't got revoke for it yet? */
	assert(commit_num == lnchn->remote.commit->commit_num-1);
	*rhash = *lnchn->their_prev_revocation_hash;
	return NULL;
}

/* We assume the tx is valid!  Don't do a blockchain.info and feed this
 * invalid transactions! */
static enum watch_result anchor_spent(struct LNchannel *lnchn,
				      const struct bitcoin_tx *tx,
				      size_t input_num,
				      void *unused)
{
	Pkt *err;
	enum state newstate;
	struct htlc_map_iter it;
	struct htlc *h;
	u64 commit_num;

	assert(input_num < tal_count(tx->input));

	/* We only ever sign single-input txs. */
	if (input_num != 0) {
		log_broken(lnchn->log, "Anchor spend by non-single input tx");
		goto unknown_spend;
	}

	/* We may have been following a different spend.  Forget it. */
	reset_onchain_closing(lnchn);

	lnchn->onchain.tx = tal_steal(lnchn, tx);
	bitcoin_txid(tx, &lnchn->onchain.txid);

	/* If we have any HTLCs we're not committed to yet, fail them now. */
	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (h->state == SENT_ADD_HTLC) {
			fail_own_htlc(lnchn, h);
		}
	}

	/* We need to resolve every output. */
	lnchn->onchain.resolved
		= tal_arrz(tx, const struct bitcoin_tx *,
			   tal_count(tx->output));

	/* A mutual close tx. */
	if (is_mutual_close(lnchn, tx)) {
		newstate = STATE_CLOSE_ONCHAIN_MUTUAL;
		err = NULL;
		resolve_mutual_close(lnchn);
	/* Our unilateral */
	} else if (structeq(&lnchn->local.commit->txid,
			    &lnchn->onchain.txid)) {
		newstate = STATE_CLOSE_ONCHAIN_OUR_UNILATERAL;
		/* We're almost certainly closed to them by now. */
		err = pkt_err(lnchn, "Our own unilateral close tx seen");
		if (!map_onchain_outputs(lnchn,
					 &lnchn->local.commit->revocation_hash,
					 tx, LOCAL,
					 lnchn->local.commit->commit_num)) {
			log_broken(lnchn->log,
				   "Can't resolve own anchor spend %"PRIu64"!",
				   lnchn->local.commit->commit_num);
			goto unknown_spend;
		}
		resolve_our_unilateral(lnchn);
	/* Must be their unilateral */
	} else if (find_their_old_tx(lnchn, &lnchn->onchain.txid,
				     &commit_num)) {
		struct sha256 *preimage, rhash;

		preimage = get_rhash(lnchn, commit_num, &rhash);
		if (!map_onchain_outputs(lnchn, &rhash, tx, REMOTE, commit_num)) {
			/* Should not happen */
			log_broken(lnchn->log,
				   "Can't resolve known anchor spend %"PRIu64"!",
				   commit_num);
			goto unknown_spend;
		}
		if (preimage) {
			newstate = STATE_CLOSE_ONCHAIN_CHEATED;
			err = pkt_err(lnchn, "Revoked transaction seen");
			resolve_their_steal(lnchn, preimage);
		} else {
			newstate = STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL;
			err = pkt_err(lnchn, "Unilateral close tx seen");
			resolve_their_unilateral(lnchn);
		}
	} else {
		/* FIXME: Log harder! */
		log_broken(lnchn->log,
			   "Unknown anchor spend!  Funds may be lost!");
		goto unknown_spend;
	}

	/* FIXME-OLD #onchain:
	 *
	 * A node MAY send a descriptive error packet in this case.
	 */
	if (err && state_can_io(lnchn->state))
		queue_pkt_err(lnchn, err);

	/* Don't need to save to DB: it will be replayed if we crash. */
	set_lnchn_state(lnchn, newstate, "anchor_spent", false);

	/* If we've just closed connection, make output close it. */
	io_wake(lnchn);

	/* FIXME-OLD #onchain:
	 *
	 * A node SHOULD fail the connection if it is not already
	 * closed when it sees the funding transaction spent.
	 */
	assert(!state_can_io(lnchn->state));

	assert(lnchn->onchain.resolved != NULL);
	watch_tx(tx, lnchn->dstate->topology,
		 lnchn, tx, check_for_resolution, NULL);

	return KEEP_WATCHING;

unknown_spend:
	/* FIXME-OLD #onchain:
	 *
	 * A node SHOULD report an error to the operator if it
	 * sees a transaction spend the funding transaction
	 * output which does not fall into one of these
	 * categories (mutual close, unilateral close, or
	 * cheating attempt).  Such a transaction implies its
	 * private key has leaked, and funds may be lost.
	 */
	/* FIXME: Save to db. */
	set_lnchn_state(lnchn, STATE_ERR_INFORMATION_LEAK, "anchor_spent", false);
	return DELETE_WATCH;
}

void lnchn_watch_anchor(struct LNchannel *lnchn, int depth)
{
	struct chain_topology *topo = lnchn->dstate->topology;

	log_debug_struct(lnchn->log, "watching for anchor %s",
			 struct sha256_double, &lnchn->anchor.txid);
	log_add(lnchn->log, " to hit depth %i", depth);

	lnchn->anchor.ok_depth = depth;
	watch_txid(lnchn, topo, lnchn,
		   &lnchn->anchor.txid, anchor_depthchange, NULL);
	watch_txo(lnchn, topo, lnchn, &lnchn->anchor.txid, 0, anchor_spent, NULL);
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

/* Sets up the initial cstate and commit tx for both nodes: false if
 * insufficient funds. */
bool setup_first_commit(struct LNchannel *lnchn)
{
	bool to_them_only, to_us_only;

	assert(!lnchn->local.commit->tx);
	assert(!lnchn->remote.commit->tx);

	/* Revocation hashes already filled in, from pkt_open */
	lnchn->local.commit->cstate = initial_cstate(lnchn->local.commit,
						    lnchn->anchor.satoshis,
						    lnchn->local.commit_fee_rate,
						    lnchn->local.offer_anchor ?
						    LOCAL : REMOTE);
	if (!lnchn->local.commit->cstate)
		return false;

	lnchn->remote.commit->cstate = initial_cstate(lnchn->remote.commit,
						     lnchn->anchor.satoshis,
						     lnchn->remote.commit_fee_rate,
						     lnchn->local.offer_anchor ?
						     LOCAL : REMOTE);
	if (!lnchn->remote.commit->cstate)
		return false;

	lnchn->local.commit->tx = create_commit_tx(lnchn->local.commit,
						  lnchn,
						  &lnchn->local.commit->revocation_hash,
						  lnchn->local.commit->cstate,
						  LOCAL, &to_them_only);
	bitcoin_txid(lnchn->local.commit->tx, &lnchn->local.commit->txid);

	lnchn->remote.commit->tx = create_commit_tx(lnchn->remote.commit,
						   lnchn,
						   &lnchn->remote.commit->revocation_hash,
						   lnchn->remote.commit->cstate,
						   REMOTE, &to_us_only);
	assert(to_them_only != to_us_only);

	/* If we offer anchor, their commit is to-us only. */
	assert(to_us_only == lnchn->local.offer_anchor);
	bitcoin_txid(lnchn->remote.commit->tx, &lnchn->remote.commit->txid);

	lnchn->local.staging_cstate = copy_cstate(lnchn, lnchn->local.commit->cstate);
	lnchn->remote.staging_cstate = copy_cstate(lnchn, lnchn->remote.commit->cstate);

	return true;
}

static struct io_plan *lnchn_reconnect(struct io_conn *conn, struct LNchannel *lnchn)
{
	/* In case they reconnected to us already. */
	if (lnchn->conn)
		return io_close(conn);

	log_debug(lnchn->log, "Reconnected, doing crypto...");
	lnchn->conn = conn;
	assert(!lnchn->connected);

	assert(lnchn->id);
	return lnchn_crypto_setup(conn, lnchn->dstate,
				 lnchn->id, lnchn->log,
				 crypto_on_reconnect_out, lnchn);
}

/* We can't only retry when we want to send: they may want to send us
 * something but not be able to connect (NAT).  So keep retrying.. */
static void reconnect_failed(struct io_conn *conn, struct LNchannel *lnchn)
{
	/* Already otherwise connected (ie. they connected in)? */
	if (lnchn->conn) {
		log_debug(lnchn->log, "reconnect_failed: already connected");
		return;
	}

	log_debug(lnchn->log, "Setting timer to re-connect");
	new_reltimer(&lnchn->dstate->timers, lnchn, lnchn->dstate->config.poll_time,
		     try_reconnect, lnchn);
}

static struct io_plan *init_conn(struct io_conn *conn, struct LNchannel *lnchn)
{
	struct addrinfo a;
	struct LNchannel_address *addr = find_address(lnchn->dstate, lnchn->id);

	netaddr_to_addrinfo(&a, &addr->addr);
	return io_connect(conn, &a, lnchn_reconnect, lnchn);
}

static void try_reconnect(struct LNchannel *lnchn)
{
	struct io_conn *conn;
	struct LNchannel_address *addr;
	char *name;
	int fd;

	/* Already reconnected? */
	if (lnchn->conn) {
		log_debug(lnchn->log, "try_reconnect: already connected");
		return;
	}

	addr = find_address(lnchn->dstate, lnchn->id);
	if (!addr) {
		log_debug(lnchn->log, "try_reconnect: no known address");
		return;
	}

	fd = socket(addr->addr.saddr.s.sa_family, addr->addr.type,
		    addr->addr.protocol);
	if (fd < 0) {
		log_broken(lnchn->log, "do_reconnect: failed to create socket: %s",
			   strerror(errno));
		lnchn_fail(lnchn, __func__);
		return;
	}

	assert(!lnchn->conn);
	conn = io_new_conn(lnchn->dstate, fd, init_conn, lnchn);
	name = netaddr_name(lnchn, &addr->addr);
	log_debug(lnchn->log, "Trying to reconnect to %s", name);
	tal_free(name);
	io_set_finish(conn, reconnect_failed, lnchn);
}

void reconnect_lnchns(struct lightningd_state *dstate)
{
	struct LNchannel *lnchn;

	list_for_each(&dstate->lnchns, lnchn, list)
		try_reconnect(lnchn);
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

static void json_add_abstime(struct json_result *response,
			     const char *id,
			     const struct abs_locktime *t)
{
	json_object_start(response, id);
	if (abs_locktime_is_seconds(t))
		json_add_num(response, "second", abs_locktime_to_seconds(t));
	else
		json_add_num(response, "block", abs_locktime_to_blocks(t));
	json_object_end(response);
}

static void json_add_htlcs(struct json_result *response,
			   const char *id,
			   struct LNchannel *lnchn,
			   enum side owner)
{
	struct htlc_map_iter it;
	struct htlc *h;
	const struct htlc_map *htlcs = &lnchn->htlcs;

	json_array_start(response, id);
	for (h = htlc_map_first(htlcs, &it); h; h = htlc_map_next(htlcs, &it)) {
		if (htlc_owner(h) != owner)
			continue;

		/* Ignore completed HTLCs. */
		if (htlc_is_dead(h))
			continue;

		json_object_start(response, NULL);
		json_add_u64(response, "msatoshi", h->msatoshi);
		json_add_abstime(response, "expiry", &h->expiry);
		json_add_hex(response, "rhash", &h->rhash, sizeof(h->rhash));
		json_add_string(response, "state", htlc_state_name(h->state));
		json_object_end(response);
	}
	json_array_end(response);
}

/* FIXME: add history command which shows all prior and current commit txs */

/* FIXME: Somehow we should show running DNS lookups! */
static void json_getlnchns(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *p;
	struct json_result *response = new_json_result(cmd);

	json_object_start(response, NULL);
	json_array_start(response, "lnchns");
	list_for_each(&cmd->dstate->lnchns, p, list) {
		const struct channel_state *last;

		json_object_start(response, NULL);
		json_add_string(response, "name", log_prefix(p->log));
		json_add_string(response, "state", state_name(p->state));

		if (p->id)
			json_add_pubkey(response, "lnchnid", p->id);

		json_add_bool(response, "connected", p->connected);

		/* FIXME: Report anchor. */

		if (!p->local.commit || !p->local.commit->cstate) {
			json_object_end(response);
			continue;
		}
		last = p->local.commit->cstate;

		json_add_num(response, "our_amount", last->side[LOCAL].pay_msat);
		json_add_num(response, "our_fee", last->side[LOCAL].fee_msat);
		json_add_num(response, "their_amount", last->side[REMOTE].pay_msat);
		json_add_num(response, "their_fee", last->side[REMOTE].fee_msat);
		json_add_htlcs(response, "our_htlcs", p, LOCAL);
		json_add_htlcs(response, "their_htlcs", p, REMOTE);
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getlnchns_command = {
	"getlnchns",
	json_getlnchns,
	"List the current lnchns",
	"Returns a 'lnchns' array"
};
AUTODATA(json_command, &getlnchns_command);

static void json_gethtlcs(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct LNchannel *lnchn;
	jsmntok_t *lnchnidtok, *resolvedtok;
	bool resolved = false;
	struct json_result *response = new_json_result(cmd);
	struct htlc *h;
	struct htlc_map_iter it;

	if (!json_get_params(buffer, params,
			     "lnchnid", &lnchnidtok,
			     "?resolved", &resolvedtok,
			     NULL)) {
		command_fail(cmd, "Need lnchnid");
		return;
	}

	lnchn = find_lnchn_json(cmd->dstate, buffer, lnchnidtok);
	if (!lnchn) {
		command_fail(cmd, "Could not find lnchn with that lnchnid");
		return;
	}

	if (resolvedtok && !json_tok_bool(buffer, resolvedtok, &resolved)) {
		command_fail(cmd, "resolved must be true or false");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "htlcs");
	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h; h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (htlc_is_dead(h) && !resolved)
			continue;

		json_object_start(response, NULL);
		json_add_u64(response, "id", h->id);
		json_add_string(response, "state", htlc_state_name(h->state));
		json_add_u64(response, "msatoshi", h->msatoshi);
		json_add_abstime(response, "expiry", &h->expiry);
		json_add_hex(response, "rhash", &h->rhash, sizeof(h->rhash));
		if (h->r)
			json_add_hex(response, "r", h->r, sizeof(*h->r));
		if (htlc_owner(h) == LOCAL) {
			json_add_num(response, "deadline", h->deadline);
			if (h->src) {
				json_object_start(response, "src");
				json_add_pubkey(response,
						"lnchnid", h->src->lnchn->id);
				json_add_u64(response, "id", h->src->id);
				json_object_end(response);
			}
		} else {
			if (h->routing)
				json_add_hex(response, "routing",
					     h->routing, tal_count(h->routing));
		}
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command gethtlcs_command = {
	"gethtlcs",
	json_gethtlcs,
	"List HTLCs for {lnchn}; all if {resolved} is true.",
	"Returns a 'htlcs' array"
};
AUTODATA(json_command, &gethtlcs_command);

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

static const struct json_command dev_newhtlc_command = {
	"dev-newhtlc",
	json_newhtlc,
	"Offer {lnchnid} an HTLC worth {msatoshi} in {expiry} (block number) with {rhash}",
	"Returns { id: u64 } result on success"
};
AUTODATA(json_command, &dev_newhtlc_command);

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
static const struct json_command dev_output_command = {
	"dev-output",
	json_output,
	"Enable/disable any messages to lnchn {lnchnid} depending on {enable}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_output_command);

static const struct json_command dev_disconnect_command = {
	"dev-disconnect",
	json_disconnect,
	"Force a disconnect with lnchn {lnchnid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_disconnect_command);

static const struct json_command dev_reconnect_command = {
	"dev-reconnect",
	json_reconnect,
	"Force a reconnect with lnchn {lnchnid}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_reconnect_command);

static const struct json_command dev_signcommit_command = {
	"dev-signcommit",
	json_signcommit,
	"Sign and return the current commit with lnchn {lnchnid}",
	"Returns a hex string on success"
};
AUTODATA(json_command, &dev_signcommit_command);