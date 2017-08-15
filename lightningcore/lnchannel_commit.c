
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
        lnchn_add_their_commit(lnchn, &ci->txid, ci->commit_num);

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


