
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

static bool check_config_compatible(const struct lightningd_state *dstate,
    const struct LNchannel_config *nego_config)
{
    u32 delay_blk = rel_locktime_to_blocks(&nego_config->delay);
    u64 feerate = get_feerate(dstate->topology);

    if (delay_blk > dstate->config.locktime_max)
        return false;
	if (nego_config->min_depth > dstate->config.anchor_confirms_max)
		return false;
	if (nego_config->initial_fee_rate
	    < feerate * dstate->config.commitment_fee_min_percent / 100)
		return false;
	if (dstate->config.commitment_fee_max_percent != 0
	    && (nego_config->initial_fee_rate
		> feerate * dstate->config.commitment_fee_max_percent/100))
		return false;

    return true;
}

void lnchn_negotiate_from_remote(struct LNchannel *lnchn)
{
    /*
        TODO: here just simply set local the same as remote, later we should 
        derive suitable values from configuration
    */
    lnchn->local.locktime = lnchn->remote.locktime;
	lnchn->local.mindepth = lnchn->remote.mindepth;

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

///* We may have gone down before broadcasting the anchor.  Try again. */
//void rebroadcast_anchors(struct lightningd_state *dstate)
//{
//	struct LNchannel *lnchn;
//
//	list_for_each(&dstate->lnchns, lnchn, list) {
//		if (!state_is_waiting_for_anchor(lnchn->state))
//			continue;
//		if (!lnchn->anchor.ours)
//			continue;
//		if (!bitcoin_create_anchor(lnchn))
//			lnchn_fail(lnchn, __func__);
//		else
//			broadcast_tx(lnchn->dstate->topology,
//				     lnchn, lnchn->anchor.tx, NULL);
//	}
//}

/* Sets up the initial cstate and commit tx for both nodes: false if
 * insufficient funds. */
static bool setup_first_commit(struct LNchannel *lnchn)
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
						  LOCAL, &to_them_only, NULL);
	bitcoin_txid(lnchn->local.commit->tx, &lnchn->local.commit->txid);

	lnchn->remote.commit->tx = create_commit_tx(lnchn->remote.commit,
						   lnchn,
						   &lnchn->remote.commit->revocation_hash,
						   lnchn->remote.commit->cstate,
						   REMOTE, &to_us_only, NULL);
	assert(to_them_only != to_us_only);

	/* If we offer anchor, their commit is to-us only. */
	assert(to_us_only == lnchn->local.offer_anchor);
	bitcoin_txid(lnchn->remote.commit->tx, &lnchn->remote.commit->txid);

	lnchn->local.staging_cstate = copy_cstate(lnchn, lnchn->local.commit->cstate);
	lnchn->remote.staging_cstate = copy_cstate(lnchn, lnchn->remote.commit->cstate);

	return true;
}

static bool lnchn_first_open(struct LNchannel *lnchn, 
    const struct pubkey *chnid,
    bool offer_anchor) {

    lnchn->id = tal_dup(lnchn, struct pubkey, chnid);
    lnchn->local.commit_fee_rate = desired_commit_feerate(lnchn->dstate);
    log_debug(lnchn->log, "Using local fee rate %"PRIu64, lnchn->local.commit_fee_rate);

    lnchn->local.offer_anchor = offer_anchor;
    lnchn->remote.offer_anchor = !offer_anchor;

    //TODO: add redeem addr option
    return lnchn_crypto_on(lnchn, NULL);

}

/* Crypto is on, we are live. */
static bool lnchn_crypto_on(struct LNchannel *lnchn, char *redeem_addr)
{
    struct bitcoin_address redeem_addr;

	lnchn_secrets_init(lnchn);

    char *useaddr = redeem_addr ? redeem_addr : lnchn->dstate->default_redeem_address;
    if (!bitcoin_from_base58(&lnchn->redeem_addr, useaddr, strlen(useaddr))) {
        log_broken(lnchn->log, "can't get bitcoin address from {%s}", useaddr);
        return false;
    }
    
    log_info(lnchn->log, "set redeem address as {%s}", useaddr);
    internal_set_lnchn_state(lnchn, STATE_OPEN_WAIT_FOR_OPENPKT, __func__, true);

	lnchn_get_revocation_hash(lnchn, 0, &lnchn->local.next_revocation_hash);
    return true;
}

static void send_open_message(struct LNchannel *lnchn)
{
    struct LNchannel_config config;
    struct pubkey *ck[2];

    config.initial_fee_rate = lnchn->local.commit_fee_rate;
    config.min_depth = lnchn->local.mindepth;
    config.delay = lnchn->local.locktime;
    //TODO: acceptor should indicate a minium (or supposed) value he will accept
    config.purpose_satoshi = 0;

    ck[0] = &lnchn->local.commitkey;
    ck[1] = &lnchn->local.finalkey;

    lite_msg_open(lnchn->dstate->message_svr, lnchn->id, 
        &config, &lnchn->local.next_revocation_hash, ck);
}

static void send_anchor_message(struct LNchannel *lnchn)
{
    struct sha256 next_hash;
    ecdsa_signature *sig = NULL;
    /*yes, we calculate this rev-hash two times: trival overhead*/
    lnchn_get_revocation_hash(lnchn, 1, &next_hash);

    lite_msg_anchor(lnchn->dstate->message_svr, lnchn->id,
        &lnchn->anchor.txid, lnchn->anchor.index, 
        lnchn->anchor.satoshis, &next_hash);
}

static void send_first_commit_message(struct LNchannel *lnchn)
{
    struct sha256 next_hash;
    ecdsa_signature *sig = NULL;
    /*yes, we calculate this rev-hash two times: trival overhead*/
    lnchn_get_revocation_hash(lnchn, 1, &next_hash);
    
    assert(lnchn->remote.commit);

    lite_msg_first_commit(lnchn->dstate->message_svr, lnchn->id,
       &next_hash, lnchn->remote.commit->sig);
}



void internal_openphase_retry_msg(struct LNchannel *lnchn)
{
    switch (lnchn->state) {
    case STATE_OPEN_WAIT_FOR_OPENPKT:
        send_open_message(lnchn); break;
    case STATE_OPEN_WAIT_FOR_CREATEANCHOR:/* local notify, not message*/
        lite_anchor_pay_notify(lnchn->dstate->payment, lnchn); break;
    case STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT:
        send_anchor_message(lnchn); break;
    case STATE_OPEN_WAIT_FOR_ANCHORPKT:
        break;
    default://any else states no need a retry msg
        break;
    }
}

bool lnchn_notify_open_remote(struct LNchannel *lnchn, 
    const struct pubkey *chnid,                /*if replay from remote, this is NULL*/
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash, /*first hash*/
    const struct pubkey *remote_key[2] /*commit key and final key*/    
)
{
	struct commit_info *ci;

    if (lnchn->state != STATE_INIT ||
        lnchn->state != STATE_OPEN_WAIT_FOR_OPENPKT) {
        //consider message is duplicated and omit it
        return true;
    }

    if (!check_config_compatible(lnchn->dstate, nego_config)) {
        //TODO: print out the config
        log_broken(lnchn->log, "Not compatible config for channel");

        internal_lnchn_fail_on_notify(lnchn, "Config is not compatible");
        return false;
    }

    if (lnchn->state == STATE_INIT) {
        assert(chnid != NULL && nego_config != NULL);
        /*accept side*/
        if (!lnchn_first_open(lnchn, chnid, false)) {
            internal_lnchn_fail_on_notify(lnchn, "open failure");
            return false;
        }

        db_start_transaction(lnchn);
        db_create_lnchn(lnchn);
    }
    else {
        /*invoke side*/
        assert(lnchn->state == STATE_OPEN_WAIT_FOR_OPENPKT 
            && !lnchn->remote.offer_anchor);
        db_start_transaction(lnchn);
    }

    //update remote data and corresponding local one
    lnchn->remote.commit_fee_rate = nego_config->initial_fee_rate;
    log_debug(lnchn->log, "Using remote fee rate %"PRIu64, lnchn->remote.commit_fee_rate);
    lnchn->remote.locktime = nego_config->delay;
	lnchn->remote.mindepth = nego_config->min_depth;

    lnchn_negotiate_from_remote(lnchn);

    memcpy(&lnchn->remote.commitkey, remote_key[0], sizeof(struct pubkey));
    memcpy(&lnchn->remote.finalkey, remote_key[1], sizeof(struct pubkey));
    memcpy(&lnchn->remote.next_revocation_hash, revocation_hash, sizeof(struct sha256));

	db_set_visible_state(lnchn);

	/* Witness script for anchor. */
	lnchn->anchor.witnessscript
		= bitcoin_redeem_2of2(lnchn,
				      &lnchn->local.commitkey,
				      &lnchn->remote.commitkey);

    internal_set_lnchn_state(lnchn,  lnchn->state == STATE_INIT ? 
        STATE_OPEN_WAIT_FOR_ANCHORPKT : STATE_OPEN_WAIT_FOR_CREATEANCHOR, 
        __func__, true);

    if (db_commit_transaction(lnchn) != NULL) {
        internal_lnchn_fail_on_notify(lnchn, "open db failure");
        return false;
    }
        
    if (lnchn->state == STATE_OPEN_WAIT_FOR_CREATEANCHOR)
        lite_anchor_pay_notify(lnchn->dstate->payment, lnchn);
    return true;
}

bool lnchn_open_local(struct LNchannel *lnchn, const struct pubkey *chnid) {

    if (!lnchn_first_open(lnchn, chnid, true)) {           
        return false;
    }

	db_start_transaction(lnchn);
	db_create_lnchn(lnchn);

	if (db_commit_transaction(lnchn) != NULL) {
		lnchn_database_err(lnchn);
        return false;
	}

    send_open_message(lnchn);
    return true;

}

bool lnchn_open_anchor(struct LNchannel *lnchn, const struct bitcoin_tx *anchor_tx) {

    if (lnchn->state != STATE_OPEN_WAIT_FOR_ANCHORPKT) {
        return false;
    }

	//if (lnchn->local.offer_anchor) {
	//	if (!bitcoin_create_anchor(lnchn)) {
	//		db_abort_transaction(lnchn);
	//		err = pkt_err(lnchn, "Own anchor unavailable");
	//		return lnchn_comms_err(lnchn, err);
	//	}
	//	/* FIXME: Redundant with lnchn->local.offer_anchor? */
	//	lnchn->anchor.ours = true;

	//	/* This shouldn't happen! */
	//	if (!setup_first_commit(lnchn)) {
	//		db_abort_transaction(lnchn);
	//		err = pkt_err(lnchn, "Own anchor has insufficient funds");
	//		return lnchn_comms_err(lnchn, err);
	//	}
	//	set_lnchn_state(lnchn,  STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT,
	//		       __func__, true);
	//	if (db_commit_transaction(lnchn) != NULL)
	//		return lnchn_database_err(lnchn);
	//	queue_pkt_anchor(lnchn);
	//	return true;
	//} 

    lnchn->anchor.ours = true;
    lnchn->anchor.min_depth = get_block_height(lnchn->dstate->topology);

    db_start_transaction(lnchn);
    db_set_anchor(lnchn);

    internal_set_lnchn_state(lnchn,  STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT, __func__, true);

    if (db_commit_transaction(lnchn) != NULL){
        lnchn_database_err(lnchn);
        return false;
    }

    send_anchor_message(lnchn);
    return true;
}

bool lnchn_notify_anchor(struct LNchannel *lnchn, const struct pubkey *chnid,
    const struct sha256_double *txid, unsigned int index, 
    unsigned long long amount, const struct sha256 *revocation_hash
) {

    if (anchor_too_large(amount)) {
        internal_lnchn_fail_on_notify(lnchn, "Anchor millisatoshis exceeds 32 bits");
        return false;
    }     

    db_start_transaction(lnchn);

    db_new_commit_info(lnchn, LOCAL, NULL);
    db_new_commit_info(lnchn, REMOTE, NULL);
    internal_set_lnchn_state(lnchn,  STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE, __func__, true);

    if (db_commit_transaction(lnchn) != NULL){
        lnchn_database_err(lnchn);
        return false;
    }

    return true;
}

bool lnchn_notify_first_commit(struct LNmessage *msg,
    const struct sha256 *revocation_hash,
    const struct ecdsa_signature_ *sig
) {



    return false;
}


static void on_first_commit_task(const struct LNchannel* lnchn, enum outsourcing_result ret, void *cbdata)
{

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


//static void lnchn_depth_ok(struct LNchannel *lnchn)
//{
//	queue_pkt_open_complete(lnchn);
//
//	db_start_transaction(lnchn);
//
//	switch (lnchn->state) {
//	case STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE:
//		set_lnchn_state(lnchn, STATE_OPEN_WAIT_THEIRCOMPLETE,
//			       __func__, true);
//		break;
//	case STATE_OPEN_WAIT_ANCHORDEPTH:
//		lnchn_open_complete(lnchn, NULL);
//		set_lnchn_state(lnchn, STATE_NORMAL, __func__, true);
//		announce_channel(lnchn->dstate, lnchn);
//		sync_routing_table(lnchn->dstate, lnchn);
//		break;
//	default:
//		log_broken(lnchn->log, "%s: state %s",
//			   __func__, state_name(lnchn->state));
//		lnchn_fail(lnchn, __func__);
//		break;
//	}
//
//	if (db_commit_transaction(lnchn))
//		lnchn_database_err(lnchn);
//}

//static enum watch_result anchor_depthchange(struct LNchannel *lnchn,
//					    unsigned int depth,
//					    const struct sha256_double *txid,
//					    void *unused)
//{
//	log_debug(lnchn->log, "Anchor at depth %u", depth);
//
//	/* Still waiting for it to reach depth? */
//	if (state_is_waiting_for_anchor(lnchn->state)) {
//		log_debug(lnchn->log, "Waiting for depth %i",
//			  lnchn->anchor.ok_depth);
//		/* We can see a run of blocks all at once, so may be > depth */
//		if ((int)depth >= lnchn->anchor.ok_depth) {
//			lnchn_depth_ok(lnchn);
//			lnchn->anchor.ok_depth = -1;
//		}
//	} else if (depth == 0)
//		/* FIXME: Report losses! */
//		fatal("Funding transaction was unspent!");
//
//	/* Since this gets called on every new block, check HTLCs here. */
//	check_htlc_expiry(lnchn);
//
//	/* If fee rate has changed, fire off update to change it. */
//	if (want_feechange(lnchn) && state_can_commit(lnchn->state)) {
//		log_debug(lnchn->log, "fee rate changed to %"PRIu64,
//			  desired_commit_feerate(lnchn->dstate));
//		/* FIXME: If fee changes back before update, we screw
//		 * up and send an empty commit.  We need to generate a
//		 * real packet here! */
//		remote_changes_pending(lnchn);
//	}
//
//	/* FIXME-OLD #2:
//	 *
//	 * A node MUST update bitcoin fees if it estimates that the
//	 * current commitment transaction will not be processed in a
//	 * timely manner (see "Risks With HTLC Timeouts").
//	 */
//	/* Note: we don't do this when we're told to ignore fees. */
//	/* FIXME: BOLT should say what to do if it can't!  We drop conn. */
//	if (!state_is_onchain(lnchn->state) && !state_is_error(lnchn->state)
//	    && lnchn->dstate->config.commitment_fee_min_percent != 0
//	    && lnchn->local.commit->cstate->fee_rate < get_feerate(lnchn->dstate->topology)) {
//		log_broken(lnchn->log, "fee rate %"PRIu64" lower than %"PRIu64,
//			   lnchn->local.commit->cstate->fee_rate,
//			   get_feerate(lnchn->dstate->topology));
//		lnchn_fail(lnchn, __func__);
//	}
//
//	return KEEP_WATCHING;
//}

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