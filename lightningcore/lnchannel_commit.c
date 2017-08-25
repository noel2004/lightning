
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

static void add_their_commit(struct LNchannel *lnchn,
			   const struct sha256_double *txid, u64 commit_num)
{
	struct their_commit *tc = tal(lnchn, struct their_commit);
	tc->txid = *txid;
	tc->commit_num = commit_num;

	db_add_commit_map(lnchn, txid, commit_num);
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

static u64 lnchn_commitsigs_received(struct LNchannel *lnchn)
{
	return lnchn->their_commitsigs;
}

static u64 lnchn_revocations_received(struct LNchannel *lnchn)
{
	/* How many preimages we've received. */
	return -lnchn->their_preimages.min_index;
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

/* cleanning dead htlcs, mark expiry htlcs and some other cleannings ...*/
static void checkhtlcs(struct LNchannel *lnchn)
{
    //internal_htlc_update_deadline(lnchn, h);
}

struct htlcs_table {
	enum htlc_state from, to;
};

struct feechanges_table {
	enum feechange_state from, to;
};

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

struct htlc_commit_tasks
{
    struct htlc *ref_h;
    struct msg_htlc_entry* gen_entry;
};

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

/* add or remove changed htlcs */
static void resolvehtlcs(struct LNchannel *lnchn, 
    const struct htlcs_table *table,
    size_t n,
    struct htlc_commit_tasks *tasks) {

    struct htlc *h;
    size_t i, j, cnt;
    enum htlc_state new_state, old_state;
    cnt = tal_count(tasks);

    for (i = 0; i < cnt; ++i) {

        h = tasks[i].ref_h;

        assert(htlc_is_fixed(h));
        new_state = h->state;
        for (j = 0; j < n; ++j) {
            if (h->state == table[j].from) {
                new_state = table[j].to;
                break;
            }
        }

        assert(new_state == h->state);
        if (new_state == h->state)continue;

        if (!adjust_cstates(lnchn, h, h->state, new_state))
            continue;//simply pass it (so warning should have been made)

        old_state = h->state;
        htlc_changestate(h, h->state, new_state);

        if (tasks[i].gen_entry->action_type == 0) {
            if (tasks[i].gen_entry->action.del.r) {
                set_htlc_rval(lnchn, h, tasks[i].gen_entry->action.del.r);
            }                
            else if(!h->fail){//only apply when htlc is not failed explictily
                set_htlc_fail(lnchn, h, tasks[i].gen_entry->action.del.fail, 
                    tal_count(tasks[i].gen_entry->action.del.fail));
            }                
        }
        else {
            db_new_htlc(lnchn, h);
        }

        /* commit htlc */
		if (htlc_state_flags(old_state) & HTLC_ADDING) {
			db_new_htlc(lnchn, h);
			return;
		}
		db_update_htlc_state(lnchn, h, old_state);
    }
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

        f.commit_num = state->commit->commit_num + 1;//apply to next commit
        f.fee_rate = state->staging_cstate->fee_rate;
        f.side = side;

        db_new_feechange(lnchn, &f);
        return true;
    }

}

static void filterhtlcs_and_genentries(const tal_t *ctx, 
        struct LNchannel *lnchn, 
        struct msg_htlc_entry *msg_arr, /*suppose the arr is long enough to held all possible entries*/
        struct htlc_commit_tasks **add_table,
        struct htlc_commit_tasks **remove_table
    )
{
    struct htlc_map_iter it;
    struct htlc *h, *yah;
    struct htlc_commit_tasks *add_h, *rem_h;
    *add_table = tal_arr(ctx, struct htlc_commit_tasks, htlc_map_count(&lnchn->htlcs));
    *remove_table = tal_arr(ctx, struct htlc_commit_tasks, htlc_map_count(&lnchn->htlcs));

    add_h = *add_table;
    rem_h = *remove_table;

    for (h = htlc_map_first(&lnchn->htlcs, &it);
        h;
        h = htlc_map_next(&lnchn->htlcs, &it)) {

        yah = NULL;
        //for pending (purpose to added), check if it can be added now
        if (htlc_has(h, HTLC_LOCAL_F_PENDING)) {
            
            /* 
                is tip or its source has been fixed, case for a broken source 
                is rared, but in case we save some works ...
            */
            if (htlc_route_is_tip(h) || (yah 
                = lite_query_htlc_direct(lnchn->dstate->channels,
                    &h->rhash, false)) && 
                htlc_is_fixed(yah)) {

                add_h->ref_h = h;
                add_h->gen_entry = msg_arr++;
                add_h->gen_entry->rhash = &h->rhash;
                add_h->gen_entry->action_type = 1;
                add_h->gen_entry->action.add.expiry = &h->expiry;
                add_h->gen_entry->action.add.mstatoshi = h->msatoshi;
                ++add_h;
            }
        }
        //for fixed task, check if it can be resolved
        else if(htlc_is_fixed(h)){

            /* not harm even no action is taken*/
            rem_h->ref_h = h;
            rem_h->gen_entry = msg_arr;

            /*
                is end and has been resolved, or its downstream has been resolved
            */
            if ((htlc_route_is_end(h) && h->r)){
                rem_h->gen_entry->action.del.r = h->r;
            }
            else if (yah = lite_query_htlc_direct(lnchn->dstate->channels,
                    &h->rhash, true) && htlc_is_dead(yah)) {
                //*(rem_h++) = h;
                if (yah->r) {
                    /*don't take pointer only*/
                    rem_h->gen_entry->action.del.r = tal_dup(msg_arr, struct preimage, yah->r);
                }
                else {
                    assert(yah->fail);
                    rem_h->gen_entry->action.del.r = NULL;
                    rem_h->gen_entry->action.del.fail = yah->fail;
                    rem_h->gen_entry->action.del.failflag = 0;
                }
            }
            //finally check any htlc which is resolved, fail explicitly or expired
            else if (h->r) {
                rem_h->gen_entry->action.del.r = h->r;
            }
            else if (h->fail) {
                rem_h->gen_entry->action.del.fail = yah->fail;
                rem_h->gen_entry->action.del.failflag = htlc_route_is_end(h) ? 1 : 0;
            }

            else goto noaction; //well, ugly goto ...

            rem_h->gen_entry->action_type = 0;
            /* the setrval is left for resolvehtlcs, htlcs is immuatable here*/

            ++rem_h;
            ++msg_arr;
noaction:
        }

        lite_release_htlc(lnchn->dstate->channels, yah);

    }

    tal_resize(add_table, add_h - *add_table);
    tal_resize(remove_table, rem_h - *remove_table);
}

static bool check_adding_htlc_compitable(const struct msg_htlc_add* incoming, const struct htlc *purposed)
{
    //TODO: also check expiry
    return incoming->mstatoshi >= purposed->msatoshi;
}

/* update ref_htlc in tasks, and verify each one (also add and apply to staged cstate)*/
static bool verify_commit_tasks(struct LNchannel *lnchn, 
    const tal_t *ctx,
    struct msg_htlc_entry *msgs,
    size_t n,
    struct htlc_commit_tasks **tasks) {

    const tal_t *tmpctx = tal_tmpctx(ctx);
    struct htlc *h;
    struct msg_htlc_entry *t_beg, *t_end;
    struct htlc_commit_tasks *task_h;
    t_end = msgs + tal_count(tasks);

    *tasks = tal_arr(ctx, struct htlc_commit_tasks, n);
    task_h = *tasks;

    for (t_beg = msgs; t_beg != t_end; ++t_beg, ++task_h) {

        h = htlc_get_any(&lnchn->htlcs, t_beg->rhash);
        if (!h) { //fail! no corresponding htlc!
            log_broken(lnchn->log, "receive non-exist htlc notify for hash %s",
                tal_hexstr(tmpctx, &h->rhash, sizeof(h->rhash)));
            tal_free(tmpctx);
            return false;
        }

        if (t_beg->action_type == 1) {//add
            if (h->state != RCVD_ADD_HTLC || !check_adding_htlc_compitable(
                &t_beg->action.add, h)) {
                log_broken_struct(lnchn->log, "Not a pending or compatible htlc for adding: %s",
                    struct htlc, h);
                tal_free(tmpctx);
                return false;
            }

            h->msatoshi = t_beg->action.add.mstatoshi;
            h->expiry = *t_beg->action.add.expiry;
        }
        else {//removed

            if (!htlc_is_fixed(h)) {
                log_broken_struct(lnchn->log, "Not a fixed htlc for removing: %s",
                    struct htlc, h);
                tal_free(tmpctx);
                return false;
            }
            //nothing to do ...
        }

        task_h->ref_h = h;
        task_h->gen_entry = t_beg;
    }

    tal_free(tmpctx);
    return true;
}

static const char *changestates(struct LNchannel *lnchn,
				const struct htlcs_table *table,
				size_t n,
				const struct feechanges_table *ftable,
				size_t n_ftable,
				bool db_commit)
{
	struct htlc_map_iter it;
	struct htlc *h, *h_side;
	bool changed = false;
	size_t i;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {

		for (i = 0; i < n; i++) {
            //any "send purpose" can be commit after its downstream is commited
            if (htlc_has(h, HTLC_ADDING) && htlc_route_has_downstream(h)) {
                h_side = lite_query_htlc_direct(lnchn->dstate->channels,
                    &h->rhash, true);
            }
            //any "remove purpose" can be commit after its upstream is commited
            else if (htlc_has(h, HTLC_REMOVING)) {

            }
            
			if (h->state == table[i].from) {
				if (!adjust_cstates(lnchn, h,
						    table[i].from, table[i].to))
					return "accounting error";
				htlc_changestate(h, table[i].from, table[i].to);
				check_both_committed(lnchn, h);
				changed = true;
			}
		}
	}

	//if (db_commit) {
	//	if (newstate == RCVD_ADD_COMMIT || newstate == SENT_ADD_COMMIT) {
	//		db_new_htlc(h->peer, h);
	//		return;
	//	}
	//	/* These never hit the database. */
	//	if (oldstate == RCVD_REMOVE_HTLC)
	//		oldstate = SENT_ADD_ACK_REVOCATION;
	//	else if (oldstate == SENT_REMOVE_HTLC)
	//		oldstate = RCVD_ADD_ACK_REVOCATION;
	//	db_update_htlc_state(h->peer, h, oldstate);
	//}

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

	//if (db_commit) {
	//	if (newstate == RCVD_FEECHANGE_COMMIT
	//	    || newstate == SENT_FEECHANGE_COMMIT)
	//		db_new_feechange(lnchn, f);
	//	else if (newstate == RCVD_FEECHANGE_ACK_REVOCATION
	//		 || newstate == SENT_FEECHANGE_ACK_REVOCATION)
	//		db_remove_feechange(lnchn, f, oldstate);
	//	else
	//		db_update_feechange_state(lnchn, f, oldstate);
	//}

	/* FIXME-OLD #2:
	 *
	 * A node MUST NOT send an `update_commit` message which does
	 * not include any updates.
	 */
	if (!changed)
		return "no changes made";
	return NULL;
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
		//their_htlc_added(lnchn, h, NULL);
		resolve_invoice(lnchn->dstate, invoice);
		set_htlc_rval(lnchn, htlc, &invoice->r);
		command_htlc_fulfill(lnchn, htlc);
		break;
	default:
		break;
	}
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

static bool do_commit(struct LNchannel *lnchn, struct command *jsoncmd)
{
    struct commit_info *ci;
    const char *errmsg;
    static const struct htlcs_table changes[] = {
        { SENT_ADD_HTLC, SENT_ADD_COMMIT },
        { SENT_REMOVE_REVOCATION, SENT_REMOVE_ACK_COMMIT },
        { SENT_ADD_REVOCATION, SENT_ADD_ACK_COMMIT },
        { SENT_REMOVE_HTLC, SENT_REMOVE_COMMIT }
    };
    static const struct feechanges_table feechanges[] = {
        { SENT_FEECHANGE, SENT_FEECHANGE_COMMIT },
        { SENT_FEECHANGE_REVOCATION, SENT_FEECHANGE_ACK_COMMIT }
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
        add_their_commit(lnchn, &ci->txid, ci->commit_num);

    if (lnchn->state == STATE_SHUTDOWN) {
        set_lnchn_state(lnchn, STATE_SHUTDOWN_COMMITTING, __func__, true);
    }
    else {
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

bool lnchn_add_htlc(struct LNchannel *chn, u64 msatoshi,
    unsigned int expiry,
    const struct sha256 *rhash,
    const u8 route,
    enum fail_error *error_code) {

    h = internal_new_htlc(lnchn, t_beg->action.add.mstatoshi,
        t_beg->rhash, t_beg->action.add.expiry, 0, RCVD_ADD_HTLC);

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


