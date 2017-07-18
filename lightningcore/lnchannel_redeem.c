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
#include "lightninglite/c/manager.h"
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

void lnchn_update_htlc_watch(struct LNchannel *chn, const struct sha256 *rhash, struct txowatch* txo)
{
    struct htlc *h = htlc_map_get(&chn->htlcs, rhash);
    if (h == NULL) {
        log_broken(chn->log,
            "Can't find htlc %s in channel %s",
            tal_hexstr(txo, rhash, sizeof(struct sha256)),
            type_to_string(txo, struct pubkey, chn->id));
        return;
    }

    if (h->src_watch) {
        tal_free(h->src_watch);
    }

    h->src_watch = txo;
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

/* Create a HTLC fulfill transaction for onchain.tx[out_num]. */
static const struct bitcoin_tx *htlc_deliver_tx(const struct LNchannel *lnchn,
    const tal_t *ctx, const struct sha256_double *commitid, 
    u32 out_num, u64 satoshis)
{
    struct bitcoin_tx *tx = bitcoin_tx(ctx, 1, 1);
    u64 fee;

    tx->input[0].index = out_num;
    memcpy(&tx->input[0].txid, commitid, sizeof(struct sha256_double));
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

    if (fee > satoshis || is_dust(satoshis - fee)) {
        log_broken(lnchn->log, "HTLC redeem amount of %"PRIu64" won't cover fee %"PRIu64,
            satoshis, fee);
        return NULL;
    }

    tx->output[0].amount = satoshis - fee;
    return tx;
}

static struct txdeliver* create_watch_deliver_task(const tal_t *ctx, 
    struct LNchannel *lnchn, u8 *wscript, 
    const struct bitcoin_tx *commit_tx, u32 out_num,
    const struct sha256_double *commitid, const struct htlc* h) {

    struct txdeliver *task = tal(ctx, struct txdeliver);
    /* 
       two amount can be used: the output amount in commit_tx or the msatoshi in hltc,
       previous one is generated from the second when building commit_tx but 
       here we should select the most direct one (orginial code use previous)
    */
    //u64 satoshis = h->msatoshi / 1000;
    u64 satoshis = commit_tx->output[out_num].amount;

    task->wscript = wscript;
    task->deliver_tx =
        htlc_deliver_tx(lnchn, task, commitid, out_num, satoshis);

    if (task->deliver_tx == NULL) {
        //fail tx, so fail task
        return NULL;
    }

    //sign for a "immediately" redeem (with preimage or revocation hash)
    lnchn_sign_htlc(lnchn, task->deliver_tx, wscript, &task->sig_nolocked);

    //if htlc is ours, we also set locktime and sign the "expire" redeem
    if (htlc_owner(h) == LOCAL) {
        task->sig = tal(ctx, ecdsa_signature);
        task->deliver_tx->lock_time = h->expiry.locktime;
        lnchn_sign_htlc(lnchn, task->deliver_tx, wscript, task->sig);
    }

    return task;
}

static struct txdeliver *create_watch_our_redeem_task(const tal_t *ctx,
    struct LNchannel *lnchn, u8 *wscript,
    const struct bitcoin_tx *commit_tx, u32 out_num, 
    const struct sha256 *rhash,
    const struct sha256_double *commitid) {

    struct txdeliver *task = tal(ctx, struct txdeliver);

    //we care about redeeming our commit
    //commit_output_to_us(ctx, lnchn, )

    return task;
}

static bool create_watch_output_task(const tal_t *ctx,
    struct LNchannel *lnchn, u32 out_num,
    const struct sha256_double *commitid, const struct htlc* h,
    struct lnwatch_task *outtask) {

    struct txowatch* txo = NULL;
    const struct LNchannel* srcchn = lite_query_htlc_src(lnchn->dstate->channels, &h->rhash);

    if (srcchn == NULL)return false;

    assert(srcchn->local.commit);

    memcpy(&outtask->commitid, &srcchn->local.commit->txid, sizeof(*commitid));
    outtask->preimage = NULL;
    outtask->redeem_tx = NULL;
    outtask->htlctxs = tal(ctx, struct lnwatch_htlc_task);

    //set the only lnwatch_htlc_task
    memcpy(&outtask->htlctxs->rhash, &h->rhash, sizeof(h->rhash));

    outtask->htlctxs->txdeliver = NULL;
    txo = tal(ctx, struct txowatch);
    memcpy(&txo->commitid, commitid, sizeof(*commitid));
    txo->output_num = out_num;
    outtask->htlctxs->txowatch = txo;

    //task done, we also update the srcchn ...
    lnchn_update_htlc_watch(srcchn, &h->rhash, tal_dup(srcchn, struct txowatch, txo));

    //final release
    lite_release_query_chn(lnchn->dstate->channels, srcchn);

    return true;
}

/* create a watch task from visible state (current commit)*/
struct lnwatch_task* lnchn_inner_create_watch_task(struct LNchannel *lnchn,
    const tal_t *ctx,
    const struct bitcoin_tx *commit_tx, 
    const struct sha256 *rhash,
    enum side side)
{
    struct htlc_map_iter it;
    struct htlc *h;
    struct htlc_output_map *hmap;
    int committed_flag = HTLC_FLAG(side, HTLC_F_COMMITTED);
    struct lnwatch_task* tasks = tal_arr(ctx, struct lnwatch_task, tal_count(commit_tx->output));
    struct lnwatch_htlc_task* htlctaskscur;
    size_t active_tasks = 1;
    size_t search_i = 0;

    /* default task for the commit_tx */
    bitcoin_txid(commit_tx, &tasks->commitid);
    /* have at most delivertasks equal to the output of commit_tx*/
    tasks->htlctxs = tal_arr(ctx, struct lnwatch_htlc_task, tal_count(commit_tx->output));
    htlctaskscur = tasks->htlctxs;

    tasks->preimage = NULL;

    //buid the output_map like handling an on-chain tx 
    //do not use the output_map of htlcs, instead, we do it "reversely", which 
    //should find corresponding output in commit_tx very fast 
    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        size_t outnum;
        u8* wscript;

        if (!htlc_has(h, committed_flag))
            continue;

        wscript = wscript_for_htlc(ctx, lnchn, h, rhash, side);
        //find the corresponding output for this htlc
        outnum = find_output_from_commit_tx(commit_tx, wscript, &search_i);
        if (outnum >= tal_count(commit_tx->output)) {
            log_debug(lnchn->log, 
                "htlc %s has no correponding output in commit-tx", 
                tal_hexstr(ctx, &h->rhash, sizeof(h->rhash)));
            continue;
        }

        //add deliver task for each active htlc
        memcpy(&htlctaskscur->rhash, &h->rhash, sizeof(h->rhash));
        htlctaskscur->txowatch = NULL;
        htlctaskscur->txdeliver = create_watch_deliver_task(ctx, lnchn, wscript,
            commit_tx, outnum, &tasks->commitid, h);

        //create additional txo watch task
        if (htlc_owner(h) == LOCAL && h->src_expiry 
            && active_tasks < tal_count(commit_tx->output)) {

            if(create_watch_output_task(ctx, lnchn, outnum, 
                &tasks->commitid, h, tasks + active_tasks))
                ++active_tasks;
        }

        htlctaskscur++;
    }

    if (htlctaskscur == tasks->htlctxs) {
        tasks->htlctxs = NULL; //no htlc tasks ...
    }
    else {
        tal_resize(&tasks->htlctxs, htlctaskscur - tasks->htlctxs);
    }
    
    tal_resize(&tasks, active_tasks);
    return tasks;
}

void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo)
{

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