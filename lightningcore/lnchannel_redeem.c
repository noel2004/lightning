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

void internal_update_htlc_watch(struct LNchannel *chn, const struct sha256 *rhash, struct txowatch* txo)
{
    struct htlc *h = htlc_map_get(&chn->htlcs, rhash);
    if (h == NULL) {
        log_broken(chn->log,
            "Can't find htlc %s in channel %s",
            tal_hexstr(txo, rhash, sizeof(struct sha256)),
            type_to_string(txo, struct pubkey, chn->id));
        return;
    }

    //htlc have upstream must not have src 
    assert(!h->src_expiry);

    if (h->upstream_watch) {
        tal_free(h->upstream_watch);
    }

    h->upstream_watch = txo;
}

void internal_resolve_htlc(struct LNchannel *lnchn, const struct sha256 *rhash)
{

}

static struct bitcoin_tx *generate_deliver_tx(const struct LNchannel *lnchn,
    const tal_t *ctx, const struct sha256_double *commitid,
    u32 out_num, u64 satoshis, size_t estimated_txsize)
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

    fee = fee_by_feerate(83 + estimated_txsize / 4, get_feerate(lnchn->dstate->topology));

    if (fee > satoshis || is_dust(satoshis - fee)) {
        log_broken(lnchn->log, "HTLC redeem amount of %"PRIu64" won't cover fee %"PRIu64,
            satoshis, fee);
        return NULL;
    }

    tx->output[0].amount = satoshis - fee;
    return tx;
}

/* Create a spend fulfill transaction for onchain.tx[out_num]. */
static struct bitcoin_tx *redeem_deliver_tx(const struct LNchannel *lnchn,
    const tal_t *ctx, const struct sha256_double *commitid, 
    u32 out_num, u64 satoshis)
{
    /* Witness length can vary, due to DER encoding of sigs, but we
    * use 176 from an example run. */
    return generate_deliver_tx(lnchn, ctx, commitid, out_num, satoshis, 176);
}

/* Create a HTLC fulfill transaction for onchain.tx[out_num]. */
static struct bitcoin_tx *htlc_deliver_tx(const struct LNchannel *lnchn,
    const tal_t *ctx, const struct sha256_double *commitid, 
    u32 out_num, u64 satoshis)
{
    /* Witness length can vary, due to DER encoding of sigs, but we
    * use 539 from an example run. */
    return generate_deliver_tx(lnchn, ctx, commitid, out_num, satoshis, 539);
}

static struct txdeliver* create_watch_deliver_task(const tal_t *ctx, 
    struct LNchannel *lnchn, u8 *wscript, 
    const struct bitcoin_tx *commit_tx, u32 out_num,
    const struct sha256_double *commitid, const struct htlc* h) {

    struct txdeliver *task = tal(ctx, struct txdeliver);
    struct bitcoin_tx *work_tx;
    /* 
       two amount can be used: the output amount in commit_tx or the msatoshi in hltc,
       previous one is generated from the second when building commit_tx but 
       here we should select the most direct one (orginial code use previous)
    */
    //u64 satoshis = h->msatoshi / 1000;
    u64 satoshis = commit_tx->output[out_num].amount;

    task->wscript = wscript;
    work_tx = htlc_deliver_tx(lnchn, task, commitid, out_num, satoshis);

    if (work_tx == NULL) {
        //fail tx, so fail task
        return NULL;
    }

    //sign for a "immediately" redeem (with preimage or revocation hash)
    lnchn_sign_htlc(lnchn, work_tx, wscript, &task->sig_nolocked);

    //if htlc is ours, we also set locktime and sign the "expire" redeem
    if (htlc_owner(h) == LOCAL) {
        task->sig = tal(ctx, ecdsa_signature);
        work_tx->lock_time = h->expiry.locktime;
        lnchn_sign_htlc(lnchn, work_tx, wscript, task->sig);
    }

    task->deliver_tx = work_tx;
    return task;
}

static struct txdeliver *create_watch_our_redeem_task(const tal_t *ctx,
    struct LNchannel *lnchn, u8 *wscript,
    const struct bitcoin_tx *commit_tx, u32 out_num,
    const struct sha256_double *commitid) {

    struct txdeliver *task = tal(ctx, struct txdeliver);
    u64 satoshis = commit_tx->output[out_num].amount;
    struct bitcoin_tx *work_tx;

    //we care about redeeming our commit
    task->wscript = wscript;
    work_tx = redeem_deliver_tx(lnchn, task, commitid, out_num, satoshis);

    if (work_tx == NULL) {
        //fail tx, so fail task
        return NULL;
    }

    lnchn_sign_spend(lnchn, work_tx, wscript, &task->sig_nolocked);
    //no lock-time, redeem tx use CSV
    task->deliver_tx = work_tx;

    return task;
}

static bool create_watch_output_task(const tal_t *ctx,
    struct LNchannel *lnchn, u32 out_num,
    const struct sha256_double *commitid, const struct htlc* h,
    struct lnwatch_task *outtask) {

    struct txowatch* txo = NULL;
    struct LNchannel* srcchn = lite_query_htlc_src(lnchn->dstate->channels, &h->rhash);

    if (srcchn == NULL)return false;

    assert(srcchn->local.commit);

    txo = tal(ctx, struct txowatch);
    memcpy(&txo->commitid, commitid, sizeof(*commitid));
    txo->output_num = out_num;

    //the task CREATED FOR source channel (NOT this channel!)
    outsourcing_task_init(outtask, &srcchn->local.commit->txid);

    //update the task with one HTLCtask
    outsourcing_htlctasks_create(ctx, outtask, 1);
    outsourcing_htlctask_init(outtask->htlctxs, &h->rhash);
    outtask->htlctxs->txowatch = txo;

    //task done, we also update the srcchn ...
    internal_update_htlc_watch(srcchn, &h->rhash, tal_dup(srcchn, struct txowatch, txo));

    //final release
    lite_release_query_chn(lnchn->dstate->channels, srcchn);
    return true;
}

/* create a watch task from visible state (current commit)*/
static struct lnwatch_task* create_watch_tasks_from_commit(struct LNchannel *lnchn,
    const tal_t *ctx,
    const struct bitcoin_tx *commit_tx, const struct sha256_double *commitid, 
    const struct sha256 *rhash,
    enum side side, struct lnwatch_task* tasks)
{
    struct htlc_map_iter it;
    struct htlc *h;
    int committed_flag = HTLC_FLAG(side, HTLC_F_COMMITTED);
    struct lnwatch_htlc_task *htlctaskscur;
    u32    htlc_deadline_min = 0;
    u8     *to_us_wscript;
    size_t redeem_outnum;
    size_t active_tasks = 1;
    size_t search_i = 0;

    /*main task (the 1st task)*/
    outsourcing_task_init(tasks, commitid);
    outsourcing_htlctasks_create(ctx, tasks, tal_count(commit_tx->output));

    /* update redeem tx*/
    redeem_outnum = find_redeem_output_from_commit_tx(commit_tx,
        commit_output_to_us(ctx, lnchn, rhash, side, &to_us_wscript),
        &search_i);
    if (redeem_outnum >= tal_count(commit_tx->output)) {
        log_debug(lnchn->log, 
                "this commit %s (%s) has no output for us", 
                tal_hexstr(ctx, commitid, sizeof(*commitid)),
                side == LOCAL ? "local" : "remote" );
        tasks->redeem_tx = NULL;
    }
    else {
        tasks->redeem_tx = create_watch_our_redeem_task(ctx, lnchn, to_us_wscript,
            commit_tx, redeem_outnum, commitid);
    }

    //if our commit, use aggressive mode
    if (side == LOCAL) {
        tasks->tasktype = OUTSOURCING_AGGRESSIVE;
        tasks->trigger_tx = commit_tx;
    }

    /* have at most deliver tasks equal to the output of commit_tx*/
    tasks->htlctxs = tal_arr(ctx, struct lnwatch_htlc_task, tal_count(commit_tx->output));
    htlctaskscur = tasks->htlctxs;

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
        outnum = find_htlc_output_from_commit_tx(commit_tx, wscript, &search_i);
        if (outnum >= tal_count(commit_tx->output)) {
            log_debug(lnchn->log, 
                "htlc %s has no correponding output in commit-tx", 
                tal_hexstr(ctx, &h->rhash, sizeof(h->rhash)));
            continue;
        }

        outsourcing_htlctask_init(htlctaskscur, &h->rhash);
        //add deliver task for each active htlc
        htlctaskscur->txdeliver = create_watch_deliver_task(ctx, lnchn, wscript,
            commit_tx, outnum, &tasks->commitid, h);

        //create additional txo watch task
        if (htlc_owner(h) == LOCAL && h->src_expiry) {
            //a local htlc with source should update its source
            if(create_watch_output_task(ctx, lnchn, outnum, 
                commitid, h, tasks + active_tasks))
                ++active_tasks;
        }
        else if (htlc_owner(h) == REMOTE && tasks->tasktype == OUTSOURCING_AGGRESSIVE) {
            //in agressive mode, a remote htlc should take a twowatch
            htlctaskscur->txowatch = h->upstream_watch;
        }

        htlctaskscur++;
    }

    //finally, update htlctxs' size
    if (htlctaskscur == tasks->htlctxs) {
        tasks->htlctxs = NULL; //no htlc tasks ...
    }
    else {
        tal_resize(&tasks->htlctxs, htlctaskscur - tasks->htlctxs);
    }

    return tasks + active_tasks;
}

void lnchn_internal_watch_for_commit(struct LNchannel *chn)
{
    const tal_t *tmpctx = tal_tmpctx(chn);
    /* we have at most 2*htlc + 2 tasks (all htlcs are local and have src, plus two main task) */
    struct lnwatch_task* tasks = tal_arr(tmpctx, struct lnwatch_task,
        htlc_map_count(&chn->htlcs) * 2 + 2); 
    struct lnwatch_task* tasks_end = tasks;

    tasks_end = create_watch_tasks_from_commit(chn, tmpctx,
        chn->local.commit->tx, &chn->local.commit->txid, 
        &chn->local.commit->revocation_hash,
        LOCAL, tasks_end);

    tasks_end = create_watch_tasks_from_commit(chn, tmpctx,
        chn->remote.commit->tx, &chn->remote.commit->txid, 
        &chn->remote.commit->revocation_hash,
        REMOTE, tasks_end);

    assert(tasks_end != tasks);

    tal_resize(&tasks, tasks_end - tasks);

    outsourcing_tasks(chn->dstate->outsourcing_svr, chn, tasks, tal_count(tasks),
        /*TODO*/ NULL, NULL);

}

void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo)
{

}

static void reset_onchain_closing(struct LNchannel *lnchn, const struct bitcoin_tx *tx)
{
    struct htlc_map_iter it;
    struct htlc *h;

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

    /* We need to resolve every output. */
    lnchn->onchain.resolved
        = tal_arrz(tx, const struct bitcoin_tx *,
            tal_count(tx->output));

    /* If we have any HTLCs we're not committed to yet, fail them now. */
    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {
        if (h->state == SENT_ADD_HTLC) {
            internal_fail_own_htlc(lnchn, h);
        }
    }

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
    u8 *to_us, *to_them, *tmp;
    struct htlc_output_map *hmap;
    size_t i;
    bool   ret = true;

    lnchn->onchain.to_us_idx = lnchn->onchain.to_them_idx = -1;
    lnchn->onchain.htlcs = tal_arr(tx, struct htlc *, tal_count(tx->output));

    //it is OK to not output wscript
    to_us = commit_output_to_us(tx, lnchn, rhash, side, NULL);
    to_them = commit_output_to_them(tx, lnchn, rhash, side, NULL);

    /* Now verify each output. */
    hmap = get_htlc_output_map(tx, lnchn, rhash, side, commit_num);

    for (i = 0; i < tal_count(tx->output); i++) {
        log_debug(lnchn->log, "%s: output %zi", __func__, i);
        if (lnchn->onchain.to_us_idx == -1
            && outputscript_eq(tx->output, i, to_us)) {
            log_add(lnchn->log, " -> to us");
            lnchn->onchain.htlcs[i] = NULL;
            lnchn->onchain.to_us_idx = i;
            continue;
        }
        if (lnchn->onchain.to_them_idx == -1
            && outputscript_eq(tx->output, i, to_them)) {
            log_add(lnchn->log, " -> to them");
            lnchn->onchain.htlcs[i] = NULL;
            lnchn->onchain.to_them_idx = i;
            continue;
        }
        /* Must be an HTLC output */
        lnchn->onchain.htlcs[i] = txout_get_htlc(hmap,
            tx->output[i].script, &tmp);
        if (!lnchn->onchain.htlcs[i]) {
            log_add(lnchn->log, "no HTLC found");
            ret = false;
            continue;//well, we still handle the rest ...
        }
        tal_steal(lnchn->onchain.htlcs, lnchn->onchain.htlcs[i]);
        log_add(lnchn->log, "HTLC %s", tal_hexstr(hmap, &lnchn->onchain.htlcs[i]->rhash, 
            sizeof(lnchn->onchain.htlcs[i]->rhash)));
    }

    tal_free(hmap);
    return ret;
}

static void handle_close_tx_delivered(struct LNchannel *lnchn, const struct bitcoin_tx *tx) {
    enum state newstate;
    u64 commit_num;

    reset_onchain_closing(lnchn, tx);

    if (is_mutual_close(lnchn, tx)) {
        size_t i;

        newstate = STATE_CLOSE_ONCHAIN_MUTUAL;
        for (i = 0; i < tal_count(lnchn->onchain.tx->output); i++) {
            lnchn->onchain.resolved[i] = lnchn->onchain.tx;
        }       
        
        /* No HTLCs. */
        lnchn->onchain.htlcs = tal_arrz(lnchn->onchain.tx,
            struct htlc *,
            tal_count(tx->output));
    }
    else if (structeq(&lnchn->local.commit->txid,
        &lnchn->onchain.txid)) {
        newstate = STATE_CLOSE_ONCHAIN_OUR_UNILATERAL;

        if (!map_onchain_outputs(lnchn,
            &lnchn->local.commit->revocation_hash,
            tx, LOCAL,
            lnchn->local.commit->commit_num)) {
            log_broken(lnchn->log,
                "Can't resolve own anchor spend %"PRIu64"!",
                lnchn->local.commit->commit_num);
            newstate = STATE_ERR_INFORMATION_LEAK;
        }

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
            newstate = STATE_ERR_INFORMATION_LEAK;
        }
        if (preimage) {
            newstate = STATE_CLOSE_ONCHAIN_CHEATED;
        }
        else {
            newstate = STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL;
        }
    }
    else {
        log_broken(lnchn->log,
            "Unknown anchor spend!  Funds may be lost!");
        newstate = STATE_ERR_INFORMATION_LEAK;
    }

    internal_set_lnchn_state(lnchn, newstate, "anchor_spent", false);
}

static void handle_htlc_tx_finished(struct LNchannel *lnchn, const struct bitcoin_tx *tx,
    bool isdelivered) {

    struct htlc *h;

    //only check first input, done or fail (even we use ANYONECANPAY and SINGLE sigops later)
    if (!structeq(&lnchn->onchain.txid, &tx->input[0].txid)) {
        log_broken(lnchn->log,
                "Not correct htlc tx for corresponding task %s!",
                tal_hexstr(lnchn, &lnchn->onchain.txid, sizeof(lnchn->onchain.txid)));
        internal_set_lnchn_state(lnchn, STATE_ERR_INTERNAL, "htlc_spent", false);
        return;
    }

    if (tx->input[0].index >= tal_count(lnchn->onchain.resolved)) {
         /*outsourcing svr mus breakdown*/
        struct sha256_double txid;
        bitcoin_txid(tx, &txid);

        log_broken(lnchn->log,
                "htlc tx %s received must breakdown!",
                tal_hexstr(lnchn, &txid, sizeof(txid)));
        internal_set_lnchn_state(lnchn, STATE_ERR_BREAKDOWN, "htlc_spent", false);
        return;
    }

    h = lnchn->onchain.htlcs[tx->input[0].index];

    //if fail, it was only normal when htlc is ours
    if (!isdelivered) {
        if (htlc_owner(h) != LOCAL) {
            struct sha256_double txid;
            bitcoin_txid(tx, &txid);
            log_broken(lnchn->log,
                "redeem their htlc tx %s fail!",
                tal_hexstr(lnchn, &txid, sizeof(txid)));
            internal_set_lnchn_state(lnchn, STATE_ERR_INFORMATION_LEAK, "htlc_spent", false);
            return;
        }
    }
    else {
        //if htlc is delivered for timeout, we MUST also resolve the 
        //source htlc
        if (htlc_owner(h) == LOCAL && h->src_expiry
            && tx->lock_time != 0 /*we simply use locktime in tx to judge if it is expired-htlc tx*/
            ) {
            struct LNchannel* srcchn = lite_query_htlc_src(lnchn->dstate->channels, &h->rhash);

            if(srcchn){
                internal_resolve_htlc(srcchn, &h->rhash);
                lite_release_query_chn(lnchn->dstate->channels, srcchn);
            }            
        }
        //(for their htlc, redeem is just redeem)
    }

    //simply resolve one
    lnchn->onchain.resolved[tx->input[0].index] = tx;
}

void lnchn_notify_tx_delivered(struct LNchannel *lnchn, const struct bitcoin_tx *tx, 
    enum outsourcing_deliver ret, const struct sha256_double *taskid)
{
    struct sha256_double txid;
    bitcoin_txid(tx, &txid);

    if (structeq(&txid, taskid)) {
        //is task itself
        if (ret == OUTSOURCING_DELIVER_DONE) {
            handle_close_tx_delivered(lnchn, tx);
        }
        else if (ret == OUTSOURCING_DELIVER_FAILED) {
            //only possible is the aggressive task fail, can omit,
            //if not, just log it 
            if (!structeq(&lnchn->local.commit->txid, &txid)) {
                log_broken(lnchn->log,
                    "We encounter unexpected task tx [%s] delivered and fail",
                    tal_hexstr(lnchn, &txid, sizeof(txid)));
            }
        }
        else {
            //confirmed, just trigger a verify, but it should always no action 
            //unless the task is rare (no resolution required)

            internal_set_lnchn_state(lnchn, STATE_CLOSED, "deliver_confirmed", false);
        }
    }
    else {
        //first we check if the tx belong to corresponding task
        if (!lnchn->onchain.tx || !structeq(&lnchn->onchain.txid, taskid)) {
            log_broken(lnchn->log,
                "We encounter unexpected htlc tx [%s] delivered [%d] "
                "(not belong to current task <%s>)",
                tal_hexstr(lnchn, &txid, sizeof(txid)),
                (int) ret,
                lnchn->onchain.tx ? "NOT INITED" : 
                tal_hexstr(lnchn, &lnchn->onchain.txid, sizeof(txid)));
            return;
        }

        //tx in a task, only care about failure or confirmed ...
        if (ret == OUTSOURCING_DELIVER_CONFIRMED) {
            handle_htlc_tx_finished(lnchn, tx, true);
        }
        else if (ret == OUTSOURCING_DELIVER_FAILED) {
            //should be the failure of a owned htlc, so just log it
            //and mark it as resolved
            //treat as delivered
            handle_htlc_tx_finished(lnchn, tx, false);
        }
        else {
            //deliver is just logged
        }
    }

}