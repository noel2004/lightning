#include "channel.h"
#include "db.h"
#include "log.h"
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


/*

    Some edge cases on redeeming:

    watching: may require 3x3=9 watches if both channel is under commiting status

    LOCAL (downloadsource) htlc resolvtion and outsourcing task updating: 
       * resolved on dead channel (corresponding redeem tx is delivered): 
         no action required, source's txo watching will found the delivered tx and
         update its deliver task on outsourcing service

       * TIP is resolved by invoice:
         only set the resolved htlc's preimage. if it was not committed, just consider
         as a "not paid" case

       * resolved on commiting:
         need to update source's tasks

*/

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

    farchnq = lite_query_channel_from_htlc(lnchn->dstate->channels, rhash, false);

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
static struct lnwatch_task *create_tasks_for_src(
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
    if (lnchn->rt.their_last_commit)commit_txid[2] = &lnchn->rt.their_last_commit->txid;

    channelq_map_init(&work_channelqs);

    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        struct channelq_map_iter chnq_it;
        struct LNchannelQuery *q;
        struct worked_source_channel *worked;

        if (!htlc_route_has_source(h))continue;

        q = lite_query_channel_from_htlc(lnchn->dstate->channels, &h->rhash, true);

        //should not have no corresponding source, but source can be closed
        if (!q) {
            log_debug(lnchn->log, "htlc with hash [%s] has not valid source",
                tal_hexstr(ctx, &h->rhash, sizeof(h->rhash)));
            continue;
        }

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

            if (h->r) {
                h_task->r = h->r;
                h_task->txowatch_num = 0;//this clear the watching task
            }
            else {
                struct txowatch*   srctxow;
                if (htlc_has(h, HTLC_ADDING)) {
                    /* 
                        TODO: 
                        "adding" should only for the SENT_ADD_COMMIT case, so
                        REMOTE may deliver the commited tx but LOCAL could not,
                        we may seek a better way to decide the updated txid array
                    */
                    struct sha256_double *commit_txid_updated[3] = 
                    { NULL, commit_txid[1], NULL };
                    srctxow = create_watch_subtask(ctx, h, commit_txid_updated);
                }
                else if (htlc_has(h, HTLC_REMOVING)) {
                    struct sha256_double *commit_txid_updated[3] = 
                    { NULL, NULL, commit_txid[2] };
                    srctxow = create_watch_subtask(ctx, h, commit_txid_updated);
                }
                else if (htlc_is_fixed(h)) {
                    srctxow = create_watch_subtask(ctx, h, commit_txid);
                }

                h_task->txowatchs = srctxow;
                h_task->txowatch_num = tal_count(srctxow);/*safe for NULL*/
            }
            worked = channelq_map_getnext(&work_channelqs, lite_query_anchor_txid(q), &chnq_it);
        };

        lite_release_chn(lnchn->dstate->channels, q);
       
    }

    channelq_map_clear(&work_channelqs);
    tal_free(tmpctx);
    return activetask;
}

static void create_tasks_from_revocation(
    const tal_t *ctx, struct LNchannel *lnchn, 
    struct lnwatch_task* tasks)
{
    struct sha256 *preimage = tal(ctx, struct sha256);

    outsourcing_task_init(tasks, &lnchn->rt.their_last_commit->txid);
    tasks->tasktype = OUTSOURCING_UPDATE;

    assert(lnchn->rt.their_last_commit);

    if (!shachain_get_hash(&lnchn->their_preimages,
        0xFFFFFFFFFFFFFFFFL - lnchn->rt.their_last_commit->commit_num,
        preimage)) {

        tal_free(preimage);

        return;
    }

    tasks->preimage = preimage;
}

/* create a watch task from visible state (current commit)*/
static void create_tasks_from_commit(
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

        /* in general a fixed htlc should not have preimage (or it must be resolved) */
        htlctaskscur->r = h->r;

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
    assert(chn->rt.prev_call);
    if (chn->rt.prev_call == NULL) {
        log_broken(chn->log, 
            "outsourcing is called without corresponding callback");
        tal_free(t);
        return NULL;
    }

    chn->rt.outsourcing_counter++;
    chn->rt.outsourcing_lock = true;
    t->callback = chn->rt.prev_call;
    t->chn = chn;
    t->counter = chn->rt.outsourcing_counter;

    return t;
}

static void outsourcing_impl(struct LNchannel *chn, bool commit_task[2] /*local, remote*/,
    bool watch_task, bool revo_task) {

    const tal_t *tmpctx = tal_tmpctx(chn);
    /* we have at most 2*htlc + 2 tasks (all htlcs are local and have src, plus two main task) */
    struct lnwatch_task* tasks = tal_arr(tmpctx, struct lnwatch_task,
        htlc_map_count(&chn->htlcs) * 2 + 2);
    struct lnwatch_task* tasks_end = tasks;
    struct commit_info* tmp = chn->rt.their_last_commit;

    /* if we not care about local commit, we can skip it*/
    if (commit_task[LOCAL] && chn->local.commit->sig) {
        create_tasks_from_commit(tmpctx, chn,
            LOCAL, tasks_end);
        tasks_end++;
    }

    if (commit_task[REMOTE]) {
        create_tasks_from_commit(tmpctx, chn,
            REMOTE, tasks_end);
        tasks_end++;
    }

    if (revo_task) {
        create_tasks_from_revocation(tmpctx, chn, tasks_end);
        assert(tasks_end->preimage);
        tasks_end++;

        //TODO: this is an ugly hacking
        /* 
            if we revoke a task, we do need watch for the last commit
            the watching subtask for revoked task is not effect in fact
            but we still wish to save communication cost
        */
        chn->rt.their_last_commit = NULL;
    }

    /* when commiting we deliver watching for 3 commit tx: local, remote and last remote*/
    if (watch_task) {
        tasks_end = create_tasks_for_src(tmpctx, chn, tasks_end);
    }
    
    /* we eliminated the side-effect */
    chn->rt.their_last_commit = tmp;

    tal_resize(&tasks, tasks_end - tasks);

    outsourcing_tasks(chn->dstate->outsourcing_svr, tasks, tal_count(tasks),
        outsourcing_callback_helper,
        outsourcing_invoke_helper(chn));

    tal_free(tmpctx);

}

void internal_outsourcing_for_committing(struct LNchannel *chn, enum side side, outsourcing_f f)
{
    bool commit_task[2] = { side == REMOTE, true };
    chn->rt.prev_call = f;

    outsourcing_impl(chn, commit_task, true, false);
}

void internal_outsourcing_for_commit(struct LNchannel *chn, enum side side, outsourcing_f f)
{
    bool commit_task[2] = { side == LOCAL, false };
    chn->rt.prev_call = f;

    //for commit-recv side, watch is not need to renew because the revoked task
    //remove its watching automatically
    outsourcing_impl(chn, commit_task, side == LOCAL, true);
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
    //for (h = htlc_map_first(&lnchn->htlcs, &it);
    //    h;
    //    h = htlc_map_next(&lnchn->htlcs, &it)) {
    //    if (!htlc_is_fixed(h)) {
    //        internal_fail_own_htlc(lnchn, h);
    //    }
    //}

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
    assert(lnchn->rt.their_last_commit && 
        commit_num == lnchn->rt.their_last_commit->commit_num - 1);
    if (lnchn->rt.their_last_commit)
        *rhash = lnchn->rt.their_last_commit->revocation_hash;
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
        //TODO: need to rebuild htlcs with htlcs in history
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
    size_t i, input_num;

    for (i = 0; i < tal_count(tx->input); ++i) {
        if (structeq(&lnchn->onchain.txid, &tx->input[i].txid))break;
    }
    //only check first input, done or fail (even we use ANYONECANPAY and SINGLE sigops later)
    if (i == tal_count(tx->input)) {
        log_broken(lnchn->log,
                "Not correct htlc tx for corresponding task %s!",
                tal_hexstr(lnchn, &lnchn->onchain.txid, sizeof(lnchn->onchain.txid)));
        internal_set_lnchn_state(lnchn, STATE_ERR_INTERNAL, "htlc_spent", false);
        return;
    }

    input_num = i;

    if (tx->input[input_num].index >= tal_count(lnchn->onchain.resolved)) {
         /*outsourcing svr must breakdown*/
        struct sha256_double txid;
        bitcoin_txid(tx, &txid);

        log_broken(lnchn->log,
                "htlc tx %s received must breakdown!",
                tal_hexstr(lnchn, &txid, sizeof(txid)));
        internal_set_lnchn_state(lnchn, STATE_ERR_BREAKDOWN, "htlc_spent", false);
        return;
    }

    h = lnchn->onchain.htlcs[tx->input[input_num].index];

    //if fail, it was only normal when htlc is ours (resolved by remoted)
    if (!isdelivered) {
        struct sha256_double txid;
        bitcoin_txid(tx, &txid);

        if (htlc_owner(h) != LOCAL) {
            log_broken(lnchn->log,
                "redeem their htlc tx %s fail!",
                tal_hexstr(lnchn, &txid, sizeof(txid)));
            internal_set_lnchn_state(lnchn, STATE_ERR_INFORMATION_LEAK, "htlc_spent", false);
            
        }else if(!lnchn->onchain.resolved[tx->input[input_num].index]){
            log_broken(lnchn->log,
                "htlc tx %s fail and htlc is redeemed by other unknown tx!",
                    tal_hexstr(lnchn, &txid, sizeof(txid)));
            internal_set_lnchn_state(lnchn, STATE_ERR_BREAKDOWN, "htlc_spent", false);        
        }
    }
    else {
        //if htlc is delivered for timeout, we MUST also resolve the 
        //source htlc
        if (htlc_route_has_source(h) && tx->lock_time != 0) {
            /*we simply use locktime in tx to judge if it is expired-htlc tx*/           
            struct LNchannelComm* comm = lite_comm_channel_from_htlc(lnchn->dstate->channels, &h->rhash, true);

            if(comm){
                lite_notify_chn_commit(comm);
                lite_release_comm(lnchn->dstate->channels, comm);
            }            
        }

        //(for their htlc, redeem is just redeem)
        //simply resolve one
        lnchn->onchain.resolved[tx->input[input_num].index] = tx;
    }

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

void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo,
    const struct bitcoin_tx *tx, const struct sha256_double *taskid, 
    const struct sha256 *rhash)
{
    struct preimage preimage;
    size_t i, input_num;

    /* only active htlc should receive watching notify, or we just log and omit it*/
    struct htlc *h = htlc_map_get(&chn->htlcs, rhash);

    if (!h || !htlc_is_fixed(h)) {
        log_broken(chn->log,
            "We receive unexpected htlc [%s] relatived tx delivered",
            tal_hexstr(chn, rhash, sizeof(*rhash)));
        return;
    }

    /* search input */
    for (i = 0; i < tal_count(tx->input); ++i) {
        if (structeq(&tx->input[i].txid, &txo->commitid)
            && tx->input[i].index == txo->output_num)
            break;
    }

    /* impossible, maybe server has been ruin? */
    if (i == tal_count(tx->input)) {
        log_broken(chn->log,
            "txo notify tx without corresponding watch: [%s:%d]",
                tal_hexstr(chn, &txo->commitid, sizeof(txo->commitid)));
        return;
    }

    input_num = i;
	/* FIXME-OLD #onchain:
	 *
	 * If a node sees a redemption transaction...the node MUST extract the
	 * preimage from the transaction input witness.  This is either to
	 * prove payment (if this node originated the payment), or to redeem
	 * the corresponding incoming HTLC from another peer.
	 */

	/* This is the form of all HTLC spends. */
    if (!tx->input[input_num].witness
        || tal_count(tx->input[input_num].witness) != 3
        || tal_count(tx->input[input_num].witness[1]) != sizeof(preimage)) {

        log_unusual_struct(chn->log,
            "Impossible HTLC spend %s",
            struct bitcoin_tx, tx);
        return;
    }

	/* Our timeout tx has all-zeroes, so we can distinguish it (just omit). */
    if (memeqzero(tx->input[input_num].witness[1], sizeof(preimage)))return;

	memcpy(&preimage, tx->input[input_num].witness[1], sizeof(preimage));

    if (!h->r) {
        internal_htlc_fullfill(chn, &preimage, h);
        internal_htlc_update_chain(chn, h);
    }

}


bool lnchn_check_closed(struct LNchannel *chn) {
    //TODO: check all the onchain.resolved is filled
    //TODO: check all involved htlc is in "can remove" status
    //(downloadstream must dead first if it was in htlc chain)
    return true;
}
