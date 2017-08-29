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

static struct txdeliver* create_deliver_task(const tal_t *ctx, 
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
    task->sig_nolocked = tal(ctx, ecdsa_signature);
    lnchn_sign_htlc(lnchn, work_tx, wscript, task->sig_nolocked);

    //if htlc is ours, we also set locktime and sign the "expire" redeem
    if (htlc_owner(h) == LOCAL) {
        task->sig = tal(ctx, ecdsa_signature);
        work_tx->lock_time = h->expiry.locktime;
        lnchn_sign_htlc(lnchn, work_tx, wscript, task->sig);
    }

    task->deliver_tx = work_tx;
    return task;
}

static struct txdeliver *create_our_redeem_task(const tal_t *ctx,
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

    task->sig_nolocked = tal(ctx, ecdsa_signature);
    lnchn_sign_spend(lnchn, work_tx, wscript, task->sig_nolocked);
    //no lock-time, redeem tx use CSV
    task->deliver_tx = work_tx;

    return task;
}

static struct txowatch *create_watch_subtask(const tal_t *ctx,
    const struct htlc* h, 
    struct sha256_double *commit_txid[3]) {

    size_t i;
    struct txowatch *txow, *txoi;

    txoi = txow = tal_arr(ctx, struct txowatch, 3);

    for (i = 0; i < 3; ++i) {
        if (!commit_txid[i])continue;

        txoi->output_num = h->in_commit_output[i];
        memcpy(&txoi->commitid, commit_txid + i, sizeof(commit_txid[i]));
        ++txoi;
    }

    if (txow == txoi) {
        tal_free(txow);
        return NULL;
    }
    tal_resize(&txow, txoi - txow);
    return txow;
}

static struct txowatch *create_watch_subtask_from_downsource(const tal_t *ctx,
    struct LNchannel *lnchn, const struct sha256* rhash) {

    struct LNchannelQuery *farchnq;
    const struct htlc *farh;
    struct sha256_double *commit_txid[3];
    struct txowatch *ret;

    farchnq = lite_query_channel_from_htlc(lnchn->dstate->channels, rhash, true);

    if (!farchnq) {

        log_broken(lnchn->log, "Can't find chnannel for htlc with hash [%s]",
            tal_hexstr(ctx, rhash, sizeof(*rhash)));
        return false;
    }

    farh = lite_query_htlc(farchnq, rhash);
    assert(farh);//can't fail
    if (!farh) {
        lite_release_chn(lnchn->dstate->channels, farchnq);
        return NULL;
    }

    lite_query_commit_txid(farchnq, commit_txid);
    ret = create_watch_subtask(ctx, farh, commit_txid);

    /* this is impossible, even one-side uncommit MUST impossible ...*/
    if (!ret) {
        log_broken(lnchn->log, "Target chnannel for htlc with hash [%s] has not commit yet",
            tal_hexstr(ctx, rhash, sizeof(*rhash)));
    }

    lite_release_htlc(lnchn->dstate->channels, farh);
    lite_release_chn(lnchn->dstate->channels, farchnq);
    return ret;
}

struct worked_source_channel
{
    struct sha256_double anchor_id;
    struct lnwatch_task  *worked_task;
};

/* channelq_map: anchor txid -> lite_query_channel mapping. */
static inline const struct sha256_double *channelq_key(const struct worked_source_channel *t)
{
    return &t->anchor_id;
}

static inline bool channelq_cmp(const struct worked_source_channel *t, const struct sha256_double* id)
{
    return memcmp(id, &t->anchor_id, sizeof(struct sha256_double)) == 0;
}

static inline size_t channelq_hash(const struct sha256_double* hash)
{
    size_t ret = 0;
    int i;

    for (i = 0; i < sizeof(hash->sha.u.u32) / sizeof(hash->sha.u.u32[0]); ++i)
    {
        ret += hash->sha.u.u32[i];
    }

    return ret;
}

#if !HAVE_TYPEOF
#undef HTABLE_KTYPE
#define HTABLE_KTYPE(keyof, type) struct sha256_double*
#endif

HTABLE_DEFINE_TYPE(struct worked_source_channel, channelq_key, channelq_hash, channelq_cmp, channelq_map);

/* 
    help updating channels' watching task which have source htlc 
    a little tough ...
*/
static struct lnwatch_task *create_watch_tasks_for_src(
    const tal_t *ctx,
    struct LNchannel *lnchn, struct lnwatch_task *outtask) {

    struct htlc_map_iter it;
    struct htlc *h;

    struct lnwatch_task *activetask = outtask;
    struct sha256_double *commit_txid[3] = { NULL, NULL, NULL };
    const tal_t *tmpctx = tal_tmpctx(ctx);

    struct channelq_map work_channelqs;
    
    /* init commit txid */
    if (lnchn->local.commit)commit_txid[0] = &lnchn->local.commit->txid;
    if (lnchn->remote.commit)commit_txid[1] = &lnchn->remote.commit->txid;
    if (lnchn->rt.their_last_commit_txid)commit_txid[2] = lnchn->rt.their_last_commit_txid;

    channelq_map_init(&work_channelqs);

    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        struct channelq_map_iter chnq_it;
        struct LNchannelQuery *q;
        struct worked_source_channel *worked;
        struct txowatch*   srctxow;

        if (!htlc_is_fixed(h) || !htlc_route_has_source(h))continue;

        q = lite_query_channel_from_htlc(lnchn->dstate->channels, &h->rhash, false);

        //should not have no corresponding source, but source can be closed
        if (!q || !lite_query_anchor_txid(q)) {
            log_debug(lnchn->log, "htlc with hash [%s] has not valid source",
                tal_hexstr(ctx, &h->rhash, sizeof(h->rhash)));
            if (q)lite_release_chn(lnchn->dstate->channels, q);
            continue;
        }
        
        //for one htlc, we have at most 3x3=9 watching generated (for 3 different tasks)
        srctxow = create_watch_subtask(ctx, h, commit_txid);

        worked = channelq_map_getfirst(&work_channelqs, lite_query_anchor_txid(q), &chnq_it);
        //found nothing, init it
        if (!worked) {
            struct sha256_double *src_commit_txid[3];
            size_t i;

            lite_query_commit_txid(q, src_commit_txid);

            for (i = 0; i < 3; ++i) {
                if (!src_commit_txid[i])continue;

                worked = tal(tmpctx, struct worked_source_channel);
                memcpy(&worked->anchor_id, lite_query_anchor_txid(q), sizeof(worked->anchor_id));

                outsourcing_task_init(activetask, src_commit_txid[i]);
                activetask->tasktype = OUTSOURCING_UPDATE;
                channelq_map_add(&work_channelqs, worked);

                worked->worked_task = activetask;
                activetask++;
            }

            //now we try again ...
            worked = channelq_map_getfirst(&work_channelqs, lite_query_anchor_txid(q), &chnq_it);
        }

        while(worked) {
            struct lnwatch_htlc_task *h_task;
            struct lnwatch_task *workedtask = worked->worked_task;

            if (workedtask->htlctxs) {
                size_t cur = tal_count(workedtask->htlctxs);
                tal_resize(&workedtask->htlctxs, cur);
                h_task = workedtask->htlctxs + cur;
            }
            else {
                workedtask->htlctxs = tal_arr(ctx, struct lnwatch_htlc_task, 1);
                h_task = workedtask->htlctxs;
            }
            
            outsourcing_htlctask_init(h_task, &h->rhash);
            h_task->txowatchs = srctxow;
            h_task->txowatch_num = tal_count(srctxow);

            worked = channelq_map_getnext(&work_channelqs, lite_query_anchor_txid(q), &chnq_it);
        };

        lite_release_chn(lnchn->dstate->channels, q);
       
    }

    return activetask;
}

/* create a watch task from visible state (current commit)*/
static void create_watch_tasks_from_commit(
    const tal_t *ctx, struct LNchannel *lnchn,
    enum side side, struct lnwatch_task* tasks)
{
    struct htlc_map_iter it;
    struct htlc *h;
    struct lnwatch_htlc_task *htlctaskscur;
    size_t redeem_outnum;
    u8 *to_us_wscript;

    struct commit_info *ci = side == LOCAL ? lnchn->local.commit : lnchn->remote.commit;
    struct sha256_double *commitid = &ci->txid;
    struct bitcoin_tx *commit_tx = ci->tx;
    struct sha256 *rhash = &ci->revocation_hash;

    /*main task (the 1st task)*/
    outsourcing_task_init(tasks, commitid);

    /* update redeem tx*/
    redeem_outnum = find_redeem_output_from_commit_tx(commit_tx,
        commit_output_to_us(ctx, lnchn, rhash, side, &to_us_wscript));
    if (redeem_outnum >= tal_count(commit_tx->output)) {
        log_debug(lnchn->log, 
                "this commit %s (%s) has no output for us", 
                tal_hexstr(ctx, commitid, sizeof(*commitid)),
                side == LOCAL ? "local" : "remote" );
        tasks->redeem_tx = NULL;
    }
    else {
        tasks->redeem_tx = create_our_redeem_task(ctx, lnchn, to_us_wscript,
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
    //grep output in commit_tx directly from htlc's record
    //(rebuiding history will use another mechanism, though hard)
    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        u8* wscript;

        if (!htlc_is_fixed(h))
            continue;

        wscript = wscript_for_htlc(ctx, lnchn, h, rhash, side);

        outsourcing_htlctask_init(htlctaskscur, &h->rhash);
        //add deliver task for each active htlc
        htlctaskscur->txdeliver = create_deliver_task(ctx, lnchn, wscript,
            commit_tx, h->in_commit_output[side], &tasks->commitid, h);

        if (htlc_route_has_downstream(h) && tasks->tasktype == OUTSOURCING_AGGRESSIVE) {
            //in agressive mode, a remote htlc should take a twowatch
            htlctaskscur->txowatchs = 
                create_watch_subtask_from_downsource(ctx, lnchn, &h->rhash);
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

}

struct watch_task {
    struct LNchannel *chn;
    u64    counter;
    void   (*callback)(struct LNchannel *, enum outsourcing_result, u64);
};

static void outsourcing_callback_helper(enum outsourcing_result ret, void *cbdata)
{
    struct watch_task *t = (struct watch_task *) cbdata;
    if (!t)return;

    if (t->chn->rt.outsourcing_counter != t->counter) {
        log_broken(t->chn->log, 
            "outsourcing callback has unmatched counter "PRIi64" vs "PRIi64,
            t->chn->rt.outsourcing_counter, t->counter);
        return;
    }
    t->callback(t->chn, ret, t->counter);

    /* 
        if callback not invoked another outsourcing, counter not change
        and lock is released
    */
    if (t->chn->rt.outsourcing_counter == t->counter) {
        t->chn->rt.outsourcing_lock = false;
    }
    
    tal_free(cbdata);
}

static void* outsourcing_invoke_helper(struct LNchannel *chn)
{
    struct watch_task *t = tal(chn, struct watch_task);
    assert(chn->rt.outsourcing_f);
    if (chn->rt.outsourcing_f == NULL) {
        log_broken(chn->log, 
            "outsourcing is called without corresponding callback");
        tal_free(t);
        return NULL;
    }

    chn->rt.outsourcing_counter++;
    chn->rt.outsourcing_lock = true;
    t->callback = chn->rt.outsourcing_f;
    t->chn = chn;
    t->counter = chn->rt.outsourcing_counter;
    /* callback is clear once invoked*/
    chn->rt.outsourcing_f = NULL;

    return t;
}

void internal_watch_for_commit(struct LNchannel *chn)
{
    const tal_t *tmpctx = tal_tmpctx(chn);
    /* we have at most 2*htlc + 2 tasks (all htlcs are local and have src, plus two main task) */
    struct lnwatch_task* tasks = tal_arr(tmpctx, struct lnwatch_task,
        htlc_map_count(&chn->htlcs) * 2 + 2); 
    struct lnwatch_task* tasks_end = tasks;

    create_watch_tasks_from_commit(tmpctx, chn, 
        LOCAL, tasks);

    create_watch_tasks_from_commit(tmpctx, chn,
        REMOTE, tasks + 1);

    assert(tasks_end != tasks);

    tal_resize(&tasks, tasks_end - tasks);

    outsourcing_tasks(chn->dstate->outsourcing_svr, tasks, tal_count(tasks),
        outsourcing_callback_helper, 
        outsourcing_invoke_helper(chn));

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
//        lnchn->onchain.wscripts = NULL;
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
        if (!htlc_is_fixed(h)) {
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
        if (htlc_route_has_source(h) && tx->lock_time != 0) {
            /*we simply use locktime in tx to judge if it is expired-htlc tx*/           
            struct LNchannelComm* comm = lite_comm_channel_from_htlc(lnchn->dstate->channels, &h->rhash, false);

            if(comm){
                lite_notify_chn_commit(comm);
                lite_release_comm(lnchn->dstate->channels, comm);
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