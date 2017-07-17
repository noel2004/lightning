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
    assert(commit_num == lnchn->remote.commit->commit_num - 1);
    *rhash = *lnchn->their_prev_revocation_hash;
    return NULL;
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
            lnchn->onchain.wscripts + i);
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

static void reset_onchain_closing(struct LNchannel *lnchn, const struct bitcoin_tx *tx)
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

    lnchn->onchain.tx = tal_steal(lnchn, tx);
    bitcoin_txid(tx, &lnchn->onchain.txid);
}

static void handle_anchor_spent(struct LNchannel *lnchn, const struct bitcoin_tx *tx) {

    enum state newstate;


    reset_onchain_closing(lnchn, tx);

    /* A mutual close tx. */
    if (is_mutual_close(lnchn, tx)) {
        newstate = STATE_CLOSE_ONCHAIN_MUTUAL;
        resolve_mutual_close(lnchn);
        /* Our unilateral */
    }
    else if (structeq(&lnchn->local.commit->txid,
        &lnchn->onchain.txid)) {
        newstate = STATE_CLOSE_ONCHAIN_OUR_UNILATERAL;
        /* We're almost certainly closed to them by now. */
        if (!map_onchain_outputs(lnchn,
            &lnchn->local.commit->revocation_hash,
            tx, LOCAL,
            lnchn->local.commit->commit_num)) {
            log_broken(lnchn->log,
                "Can't resolve own anchor spend %"PRIu64"!",
                lnchn->local.commit->commit_num);
        }
        resolve_our_unilateral(lnchn);
        /* Must be their unilateral */
    }
    else {
        //wrong or devil outsourcing?
    }

}

static void handle_unexpected_anchor_spent(struct LNchannel *lnchn, const struct bitcoin_tx *tx)
{
    enum state newstate;
    struct htlc_map_iter it;
    struct htlc *h;
    u64 commit_num;

    reset_onchain_closing(lnchn, tx);

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
        resolve_mutual_close(lnchn);
        /* Our unilateral */
    }
    else if (structeq(&lnchn->local.commit->txid,
        &lnchn->onchain.txid)) {
        newstate = STATE_CLOSE_ONCHAIN_OUR_UNILATERAL;
        /* We're almost certainly closed to them by now. */
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
    }
    else if (find_their_old_tx(lnchn, &lnchn->onchain.txid,
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
        }
        else {
            newstate = STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL;
            err = pkt_err(lnchn, "Unilateral close tx seen");
            resolve_their_unilateral(lnchn);
        }
    }
    else {
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
    tx->output[0].script = scriptpubkey_p2pkh(tx, &lnchn->redeem_addr);

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

/* create a watch task from visible state (current commit)*/
struct lnwatch_task* lnchn_inner_create_watch_task(const tal_t *ctx,
    struct LNchannel *lnchn, enum side side)
{
    struct htlc_map_iter it;
    struct htlc *h;
    int committed_flag = HTLC_FLAG(side, HTLC_F_COMMITTED);
    struct lnwatch_task *task = tal(ctx, struct lnwatch_task);
    struct commit_info *cip;

    if (side == LOCAL) {
        cip = lnchn->local.commit;
    }
    else {
        cip = lnchn->remote.commit;
    }

    if (cip == NULL || tal_count(cip) < 1) {
        log_broken(lnchn->log, "no commit info for side: %d", (int) side);
        tal_free(task);
        return NULL;
    }

    //always take the last (current) item
    cip = cip + (tal_count(cip) - 1);
    task->commitid = tal_dup(task, struct sha256_double, &cip->txid);

    //check htlc ...
    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        if (!htlc_has(h, committed_flag))
            continue;


    }
}

void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo)
{
    struct sha256 ctxid;

    bitcoin_txid(txo->committx, &ctxid);

    if (structeq(&ctxid, &chn->anchor.txid) == 0) {
        //anchor is spent
        //handle_unexpected_anchor_spent()
    }
    else {
        //htlc is redeemed (and resolved)

    }

    if (chn->state > STATE_MUTUAL_CLOSING) {

    }
    else {

    }
}

void lnchn_notify_tx_delivered(struct LNchannel *chn, const struct bitcoin_tx *tx)
{
    struct sha256 ctxid;

    bitcoin_txid(tx, &ctxid);

    if (structeq(&ctxid, &chn->anchor.txid) == 0) {
        //we have spent the anchor 
        //handle_anchor_spent()
    }
}