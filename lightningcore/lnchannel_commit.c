
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

static u64 lnchn_commitsigs_received(struct LNchannel *lnchn)
{
	return lnchn->their_commitsigs;
}

static u64 lnchn_revocations_received(struct LNchannel *lnchn)
{
	/* How many preimages we've received. */
	return -lnchn->their_preimages.min_index;
}


/* cleanning dead htlcs, mark expiry htlcs and some other cleannings ...*/
static void checkhtlcs(struct LNchannel *lnchn)
{
    //internal_htlc_update_deadline(lnchn, h);
}

static bool adjust_cstate_side(struct log *log, struct channel_state *cstate,
    struct htlc *h,
    enum htlc_state old, enum htlc_state new,
    enum side side)
{
    int oldf = htlc_state_flags(old), newf = htlc_state_flags(new);
    bool old_committed, new_committed;

    ///* We applied changes to staging_cstate when we first received
    // * add/remove packet, so we could make sure it was valid.  Don't
    // * do that again. */
    //if (old == SENT_ADD_HTLC || old == RCVD_REMOVE_HTLC
    //    || old == RCVD_ADD_HTLC || old == SENT_REMOVE_HTLC)
    //	return true;

    old_committed = (oldf & HTLC_FLAG(side, HTLC_F_COMMITTED));
    new_committed = (newf & HTLC_FLAG(side, HTLC_F_COMMITTED));

    if (old_committed && !new_committed) {
        if (h->r)
            cstate_fulfill_htlc(cstate, h);
        else
            cstate_fail_htlc(cstate, h);
    }
    else if (!old_committed && new_committed) {
        if (!cstate_add_htlc(cstate, h, false)) {
            log_broken_struct(log,
                "Cannot afford htlc %s",
                struct htlc, h);
            log_add_struct(log, " channel state %s",
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
    return adjust_cstate_side(lnchn->log, lnchn->remote.staging_cstate, h, old, new,
        REMOTE)
        && adjust_cstate_side(lnchn->log, lnchn->local.staging_cstate, h, old, new,
            LOCAL);
}

static void set_htlc_rval(struct LNchannel *lnchn,
    struct htlc *htlc, const struct preimage *rval)
{
    assert(!htlc->r);
    assert(!htlc->fail);
    htlc->r = tal_dup(htlc, struct preimage, rval);
//    db_htlc_fulfilled(lnchn, htlc);
}

static void set_htlc_fail(struct LNchannel *lnchn,
    struct htlc *htlc, const void *fail, size_t len)
{
    assert(!htlc->r);
    assert(!htlc->fail);
    htlc->fail = tal_dup_arr(htlc, u8, fail, len, 0);
//    db_htlc_failed(lnchn, htlc);
}

/*
    scan the tasks list again and persist data into htlcs
*/
static void db_update_htlcs(struct LNchannel *lnchn, 
    struct htlc **htlcs) {

    struct htlc *h;
    size_t i, cnt;
    cnt = tal_count(htlcs);

    for (i = 0; i < cnt; ++i) {

        h = htlcs[i];

        if (!htlc_has(h, HTLC_LOCAL_F_COMMITTED)) {
            if (h->r) {
                db_htlc_fulfilled(lnchn, h);
            }
            else if (h->fail) {//only apply when htlc is not failed explictily
                db_htlc_failed(lnchn, h);
            }
        }
        else {
            db_new_htlc(lnchn, h);
        }

        db_update_htlc_state(lnchn, h);       
    }
}

/* 
    add or remove changed htlcs, return handling task counts because
    adding maybe rejected
*/
static size_t applyhtlcchanges(struct LNchannel *lnchn, 
    enum htlc_state new_states[2], /*0: del, 1: add*/
    struct htlc **tasks) {

    struct htlc *h;
    size_t i, j, cnt;
    enum htlc_state new_state;
    cnt = tal_count(tasks);

    for (i = 0; i < cnt; ++i) {

        h = tasks[i];
        new_state = new_states[htlc_is_fixed(h) ? 0 : 1];

        if (!adjust_cstates(lnchn, h, h->state, new_state)) {
            //simply return at broken tasks! so following tasks
            //will be rejected (we suppose tasks is a priority queue)
            return i;
        }

        htlc_changestate(h, h->state, new_state);
    }

    return cnt;
}

/* the only thing should do is just dump feechange data to db*/
static void applyfeechange(struct LNchannel *lnchn, enum side side) {

    struct feechange f;
    struct LNChannel_visible_state *state = side == LOCAL ? &lnchn->local : &lnchn->remote;
    
    if (!state->commit) {
        return;//nothing to do
    }

    if (state->commit->cstate->fee_rate != state->staging_cstate->fee_rate) {
        log_debug(lnchn->log,
            "Fee rate has been changed from %"PRIu64" to "PRIu64,
            state->commit->cstate->fee_rate,
            state->staging_cstate->fee_rate
        );

        f.commit_num = state->commit->commit_num;
        f.fee_rate = state->staging_cstate->fee_rate;
        f.side = side;

        db_new_feechange(lnchn, &f);
        return true;
    }

}

/*
   final clean htlcs which can be removed (expired pending LOCAL or dead one)
*/
static void clean_htlcs(const tal_t *ctx, struct LNchannel *lnchn) {

    struct htlc_map_iter it;
    struct htlc *h;
    struct htlc **hi, **remh, **rem;
    remh = tal_arrz(ctx, struct htlc*, htlc_map_count(&lnchn->htlcs));
    rem = remh;

    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        if (htlc_has(h, HTLC_LOCAL_F_PENDING) && !h->src_expiry) {
            //TIP should not be cleaned
            if (htlc_route_is_tip(h))continue;
            //TODO: check expired
        }
        //REMOTE dead can not be removed
        else if (h->state == RCVD_REMOVE_COMMIT ||
            h->state == RCVD_DOWNSTREAM_DEAD) {
            *(rem++) = h;
        }
    }

    for (hi = remh; hi != rem; ++hi) {
        htlc_map_del(&lnchn->htlcs, hi);
    }
}

/*
   scan and update channel's htlc status
*/
static size_t scanhtlcs_forchange(const tal_t *ctx, 
    struct LNchannel *lnchn, 
    struct htlc **base,
    struct htlc ***add,
    struct htlc ***rem)
{
    struct htlc_map_iter it;
    struct htlc *h, **add_h, **rem_h, **other_h;
    *add = tal_arr(ctx, struct htlc *, htlc_map_count(&lnchn->htlcs));
    *rem = tal_arr(ctx, struct htlc *, htlc_map_count(&lnchn->htlcs));
    add_h = *add;
    rem_h = *rem;
    other_h = base;

    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        //scanning all fixed htlcs and try to resolve them ...
        if (htlc_has(h, HTLC_LOCAL_F_PENDING) && 
            (h->src_expiry ||
            htlc_route_is_tip(h))) {

            *(add_h++) = h;
        }        
        //for fixed, remote task, check if it can be resolved
        else if (htlc_owner(h) == REMOTE && 
            htlc_is_fixed(h) &&
            (h->r || h->fail)) {
            *(rem_h++) = h;
        }
        /*finally the dead REMOT htlc can be removed only if it have no source anymore*/
        else if (h->state == RCVD_DOWNSTREAM_DEAD) {            
            *(other_h++) = h;
        }
    }

    tal_resize(add, add_h - add);
    tal_resize(rem, rem_h - rem);
    return other_h - base;

}

static void fill_htlc_entry(struct msg_htlc_entry *m, 
    struct htlc **hbeg, size_t n, bool isadd) {

    size_t i;
    struct htlc *h;

    for (i = 0; i < n; ++m, ++hbeg) {

        h = *hbeg;

        m->rhash = &h->rhash;

        if (isadd) {
            m->action_type = 1;
            m->action.add.expiry = abs_locktime_to_blocks(&h->expiry);
            m->action.add.mstatoshi = h->msatoshi;
        }
        else {
            m->action_type = 0;
            if (h->r) {
                m->action.del.r = h->r;
            }
            else {
                assert(h->fail);
                m->action.del.fail = h->fail;
                m->action.del.failflag = htlc_route_is_end(h) ? 1 : 0;
            }
        }
    }


}

static bool check_adding_htlc_compitable(const struct msg_htlc_add* incoming, const struct htlc *purposed)
{
    //TODO: also check expiry
    return incoming->mstatoshi >= purposed->msatoshi;
}

/* update ref_htlc in tasks, and verify each one (also add and apply to staged cstate)*/
static bool verify_commit_tasks(const tal_t *ctx, 
    struct LNchannel *lnchn, 
    struct msg_htlc_entry *msgs,
    size_t n,
    struct htlc **tasks) {

    struct htlc *h, **task_h;
    struct msg_htlc_entry *t_beg, *t_end;
    t_end = msgs + n;

    *tasks = tal_arr(ctx, struct htlc *, n);
    task_h = *tasks;

    for (t_beg = msgs; t_beg != t_end; ++t_beg, ++task_h) {

        h = htlc_get_any(&lnchn->htlcs, t_beg->rhash);

        if (t_beg->action_type == 1) {//add
            //conflict!
            if (h && h->state != RCVD_ADD_HTLC){
                log_broken_struct(lnchn->log, "Encounter conflicted htlc for adding: %s",
                    struct htlc, h);
                return false;
            }
            else if (!h) {
                //check source
                struct htlc *yah;
                yah = lite_query_htlc_direct(lnchn->dstate->channels, t_beg->rhash, false);
                if (yah && (!htlc_route_has_source(yah) ||
                     !check_adding_htlc_compitable(&t_beg->action.add, yah))) {
                    log_broken_struct(lnchn->log, "Encounter conflicted source htlc for adding: %s",
                        struct htlc, yah);
                    lite_release_htlc(lnchn->dstate->channels, yah);
                    return false;
                }

                //create new htlc, decide routing according to !
                h = internal_new_htlc(lnchn, t_beg->action.add.mstatoshi,
                    t_beg->rhash, t_beg->action.add.expiry, yah ? 5 : 1 , RCVD_ADD_HTLC);

                htlc_map_add(&lnchn->htlcs, h); 
                lite_release_htlc(lnchn->dstate->channels, yah);
            }
        }
        else {//removed
            
            if (!h) { //fail! no corresponding htlc!
                log_broken(lnchn->log, "receive non-exist htlc notify for hash %s",
                    tal_hexstr(ctx, &h->rhash, sizeof(h->rhash)));
                return false;
            }else if (!htlc_is_fixed(h)) {
                log_broken_struct(lnchn->log, "Not a fixed htlc for removing: %s",
                    struct htlc, h);
                return false;
            }
            else if (htlc_owner(h) != LOCAL) {
                log_broken_struct(lnchn->log, "Not a local htlc for removing: %s",
                    struct htlc, h);
                return false;
            }

            if (t_beg->action.del.r ) {
                internal_htlc_fullfill(lnchn, t_beg->action.del.r, h);
            }
            else{
                assert(t_beg->action.del.fail);
                //verify we can fail the htlc
                if (htlc_owner(h) == LOCAL || /*remote can always fail our htlc*/                
                                              /*for remote, must check */
                (get_block_height(lnchn->dstate->topology) > h->deadline)){

                    internal_htlc_fail(lnchn, t_beg->action.del.fail,
                        tal_count(t_beg->action.del.fail), h);

                    lite_invoice_fail(lnchn->dstate->payment, &h->rhash,
                        t_beg->action.del.failflag == 0 || htlc_owner(h) == REMOTE ? 
                        INVOICE_CHAIN_FAIL :
                        INVOICE_CHAIN_FAIL_TEMP);
                }
                else {
                    log_broken_struct(lnchn->log, "htlc %s is required to closed but we cannot",
                        struct htlc, h);
                    return false;
                }
            }         
        }

        *task_h = h;
    }

    return true;
}


static send_commit_msg(const tal_t *ctx, struct LNchannel *lnchn) {

    //reconstruct changed htlcs and messages
    struct msg_htlc_entry* msgs, *msg_h;
    size_t i, n;

    if (!lnchn->rt.changed_htlc_cache) {

        struct htlc_map_iter it;
        struct htlc *h;
        struct htlc **changed_arr;
        changed_arr = tal_arr(lnchn, struct htlc *, htlc_map_count(&lnchn->htlcs));
        lnchn->rt.changed_htlc_cache = changed_arr;

        for (h = htlc_map_first(&lnchn->htlcs, &it);
            h;
            h = htlc_map_next(&lnchn->htlcs, &it)) {

            if (h->state == SENT_RESOLVE_HTLC ||
                h->state == SENT_ADD_COMMIT)
                *(changed_arr++) = h;
        }

        tal_resize(&lnchn->rt.changed_htlc_cache, changed_arr - lnchn->rt.changed_htlc_cache);
    }

    n = tal_count(lnchn->rt.changed_htlc_cache);
    msgs = tal_arr(ctx, struct msg_htlc_entry, n);
    msg_h = msgs;

    for (i = 0; i < n; ++i) {
        struct htlc* h = lnchn->rt.changed_htlc_cache[i];
        if (htlc_has(h, HTLC_ADDING))
            fill_htlc_entry(msg_h++, &h, 1, true);
        else if (htlc_has(h, HTLC_REMOVING))
            fill_htlc_entry(msg_h++, &h, 1, false);
    }

    tal_resize(&msgs, msg_h - msgs);
    lite_msg_commit_purpose(lnchn->dstate->message_svr, tal_count(msgs), msgs);

}

void internal_commitphase_retry_msg(struct LNchannel *lnchn)
{
    const tal_t *tmpctx = tal_tmpctx(lnchn);

    switch (lnchn->state) {
    case STATE_NORMAL_COMMITTING:
        send_commit_msg(tmpctx, lnchn); break;
    case STATE_NORMAL_COMMITTING_RECV:
        break;
    }

    tal_free(tmpctx);
}

static bool has_new_feechange_instate_side(const struct channel_state *stage_state,
    const struct channel_state *commit_state)
{
    return stage_state->fee_rate != commit_state->fee_rate;
}

static bool has_new_feechange_instate(struct LNchannel *lnchn, enum side side)
{
    return side == LOCAL ? has_new_feechange_instate_side(lnchn->local.staging_cstate,
            lnchn->local.commit->cstate) : 
        has_new_feechange_instate_side(lnchn->remote.staging_cstate,
            lnchn->remote.commit->cstate);
}

static void add_their_commit(struct LNchannel *lnchn,
    const struct sha256_double *txid, u64 commit_num)
{
    struct their_commit *tc = tal(lnchn, struct their_commit);
    tc->txid = *txid;
    tc->commit_num = commit_num;

    db_add_commit_map(lnchn, txid, commit_num);
}

inline static void update_htlc_chain(struct LNchannel *lnchn, struct htlc **changes) {
    struct htlc *h;
    size_t i, n;
    n = tal_count(changes);

    for (i = 0; i < n; ++i) internal_htlc_update_chain(lnchn, h);
}

static void on_commit_outsourcing_finish(struct LNchannel *lnchn, enum outsourcing_result ret, u64 num)
{
    struct commit_info *ci = lnchn->remote.commit;

    //outsourcing is done and we can deliver commit message
    if (ret != OUTSOURCING_OK) {
        log_broken(lnchn->log, "outsourcing service fail for %d", ret);
        internal_lnchn_temp_breakdown(lnchn, "outsourcing failure");
        return;
    }

    //first we update channel state to manager as final state
    lite_update_channel(lnchn->dstate->channels, lnchn);

    db_start_transaction(lnchn);

    db_new_commit_info(lnchn, REMOTE);
    applyfeechange(lnchn, REMOTE);

    /* We don't need to remember their commit if we don't give sig. */
    if (ci->sig)
        add_their_commit(lnchn, &ci->txid, ci->commit_num);

    internal_set_lnchn_state(lnchn, STATE_NORMAL_COMMITTING, __func__, true);


    //we should have cached a changed list for htlc
    assert(lnchn->rt.changed_htlc_cache);
    db_update_htlcs(lnchn, lnchn->rt.changed_htlc_cache);

    if (db_commit_transaction(lnchn) != NULL) {
        log_broken(lnchn->log, "db fail at %s", __func__);
        internal_lnchn_temp_breakdown(lnchn, "db fail");
        return ;
    }

    //here we can notify htlc updating
    update_htlc_chain(lnchn, lnchn->rt.changed_htlc_cache);

    internal_commitphase_retry_msg(lnchn);
}

void internal_update_commit(struct LNchannel *lnchn, enum side side)
{
    struct commit_info *ci;
    bool to_us_only;
    struct htlc **htlcs_update;
    struct LNChannel_visible_state *vside = side == REMOTE ?
        &lnchn->remote : &lnchn->local;

    //now generate commit ...
    ci = internal_new_commit_info(lnchn, vside->commit->commit_num + 1);

    /* Create new commit info for this commit tx. */
    ci->revocation_hash = lnchn->remote.next_revocation_hash;
    ci->cstate = copy_cstate(ci, vside->staging_cstate);
    ci->tx = create_commit_tx(ci, lnchn, &ci->revocation_hash,
        ci->cstate, side, &to_us_only, &htlcs_update);
    bitcoin_txid(ci->tx, &ci->txid);

    update_htlc_in_channel(lnchn, side, htlcs_update);
    tal_free(htlcs_update);

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
    tal_free(vside->commit);
    vside->commit = ci;

}

bool lnchn_do_commit(struct LNchannel *lnchn)
{
    struct commit_info *ci;
    bool to_us_only;
    const char *errmsg;
    struct htlc **add_t, **rem_t, **other_t, **htlcs_update;
    static const enum htlc_state changed_states[] = 
        { SENT_RESOLVE_HTLC, SENT_ADD_COMMIT };/*del, add*/
    bool   feechanged = has_new_feechange_instate(lnchn, REMOTE)
        || has_new_feechange_instate(lnchn, LOCAL);
    size_t applied_t;
    const tal_t *tmpctx = tal_tmpctx(lnchn);

    /* init, clear caches ...*/
    if (lnchn->rt.changed_htlc_cache) {
        tal_free(lnchn->rt.changed_htlc_cache);
        lnchn->rt.changed_htlc_cache = NULL;
    }

    other_t = tal_arr(lnchn, struct htlc*, htlc_map_count(&lnchn->htlcs));

    //find htlcs for changed ...
    applied_t = scanhtlcs_forchange(tmpctx, lnchn, other_t, &add_t, &rem_t);
    tal_resize(&other_t, applied_t);

    //we apply remove tasks, finally adding
    applied_t = applyhtlcchanges(lnchn, changed_states, rem_t);
    //all remove task should be handled
    assert(applied_t == tal_count(rem_t));

    //add_t may not applied commpletely
    applied_t = applyhtlcchanges(lnchn, changed_states, add_t);
    if (applied_t != tal_count(add_t)) {
        tal_resize(&add_t, applied_t);
    }

    applied_t += tal_count(rem_t);
    //now we can generate required messages
    if (applied_t > 0) {
        /*merge add and rem tables into others and bind it into run-time*/
        /*caution: must use a non-temporary context*/
        tal_expand(&other_t, rem_t, tal_count(rem_t));
        tal_expand(&other_t, add_t, tal_count(add_t));
        lnchn->rt.changed_htlc_cache = other_t;

//        fill_htlc_entry(msgs, rem_t, tal_count(rem_t), false);
    }
    else if(!feechanged){
        //so we have nothing to communitacte with REMOTE, just
        //dump the new status and quit ...
        if (tal_count(other_t)) {
            db_start_transaction(lnchn);

            db_update_htlcs(lnchn, other_t);

            if (db_commit_transaction(lnchn) != NULL) {
                log_broken(lnchn->log, "db fail at %s", __func__);
                internal_lnchn_temp_breakdown(lnchn, "db fail");
            }
        }

        tal_free(tmpctx);
        return false;
    }

    internal_update_commit(lnchn, REMOTE);
    //set outsourcing
    lnchn->rt.outsourcing_f = on_commit_outsourcing_finish;
    internal_outsourcing_for_commit(lnchn, LOCAL);

    tal_free(tmpctx);
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

