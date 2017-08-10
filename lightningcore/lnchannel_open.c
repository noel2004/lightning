
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

Pkt *accept_pkt_anchor(struct peer *peer, const Pkt *pkt)
{
	const OpenAnchor *a = pkt->open_anchor;

	/* They must be offering anchor for us to try accepting */
	assert(!peer->local.offer_anchor);
	assert(peer->remote.offer_anchor);

	if (anchor_too_large(a->amount))
		return pkt_err(peer, "Anchor millisatoshis exceeds 32 bits");

	proto_to_sha256(a->txid, &peer->anchor.txid.sha);
	peer->anchor.index = a->output_index;
	peer->anchor.satoshis = a->amount;
	return NULL;
}

Pkt *accept_pkt_open_commit_sig(struct peer *peer, const Pkt *pkt,
				secp256k1_ecdsa_signature *sig)
{
	const OpenCommitSig *s = pkt->open_commit_sig;

	if (!proto_to_signature(s->sig, sig))
		return pkt_err(peer, "Malformed signature");
	return NULL;
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
    set_lnchn_state(lnchn, STATE_OPEN_WAIT_FOR_OPENPKT, __func__, true);

	lnchn_get_revocation_hash(lnchn, 0, &lnchn->local.next_revocation_hash);

	/* Set up out commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	lnchn->local.commit = new_commit_info(lnchn, 0);
	lnchn->local.commit->revocation_hash = lnchn->local.next_revocation_hash;
	lnchn_get_revocation_hash(lnchn, 1, &lnchn->local.next_revocation_hash);

    send_open_message(lnchn);
    return true;

}

static void send_open_message(struct LNchannel *lnchn, bool recvside)
{
    struct LNchannel_config config;

    if (!recvside) {
        config.initial_fee_rate = lnchn->local.commit_fee_rate;
        config.min_depth = lnchn->local.mindepth;
        config.delay = lnchn->local.locktime;
    }

    lite_msg_open(lnchn->dstate->message_svr, recvside ? NULL : &config, 
        , );
}

void internal_openphase_retry_msg(struct LNchannel *lnchn)
{
    switch (lnchn->state) {
    case STATE_OPEN_WAIT_FOR_OPENPKT:
        send_open_message(lnchn);
        break;
    }
}

bool lnchn_notify_open_remote(struct LNchannel *lnchn, 
    const struct pubkey *chnid,                /*if replay from remote, this is NULL*/
    const struct LNchannel_config *nego_config,/*if replay from remote, this is NULL*/
    const struct sha256 *revocation_hash[2], /*this and next*/
    const struct pubkey *remote_key[2] /*commit key and final key*/    
)
{
	struct commit_info *ci;

    if (lnchn->state == STATE_INIT) {
        u64 feerate = get_feerate(lnchn->dstate->topology);

        assert(chnid != NULL && nego_config != NULL);

        if (!check_config_compatible(lnchn->dstate, nego_config)) {
            //TODO: print out the config
            log_broken(lnchn->log, "Not compatible config for channel");
            return false;
        }

        //TODO: add redeem addr option
        if (!lnchn_crypto_on(lnchn, NULL)) {           
            return false;
        }

        lnchn->id = tal_steal(lnchn, chnid);
        lnchn->remote.offer_anchor = true;
        //simply set local the same as remote because they are compatible
        lnchn->local.locktime = lnchn->remote.locktime = nego_config->delay;
	    lnchn->local.mindepth = lnchn->remote.mindepth = nego_config->min_depth;
	    lnchn->remote.commit_fee_rate = nego_config->initial_fee_rate;
        if (feerate > lnchn->remote.commit_fee_rate) {
            lnchn->local.commit_fee_rate = feerate - lnchn->remote.commit_fee_rate;
        }
        else {
            /* if he is generous enough */
            lnchn->local.commit_fee_rate = 0;
        }
	    log_debug(lnchn->log, "Using local fee rate %"PRIu64, lnchn->local.commit_fee_rate);

        lnchn->local.offer_anchor = false;

        db_start_transaction(lnchn);
        db_create_lnchn(lnchn);
    }
    else if (lnchn->state == STATE_OPEN_WAIT_FOR_OPENPKT) {
        db_start_transaction(lnchn);
    }
    else {
        return false;
    }	

    memcpy(&lnchn->remote.commitkey, remote_key[0], sizeof(struct pubkey));
    memcpy(&lnchn->remote.finalkey, remote_key[1], sizeof(struct pubkey));

	db_set_visible_state(lnchn);

	ci = new_commit_info(lnchn, 0);
    memcpy(&ci->revocation_hash, revocation_hash[0], sizeof(struct sha256));
    memcpy(&lnchn->remote.next_revocation_hash, revocation_hash[1], sizeof(struct sha256));

	/* Set up their commit info now: rest gets done in setup_first_commit
	 * once anchor is established. */
	lnchn->remote.commit = ci;

	/* Witness script for anchor. */
	lnchn->anchor.witnessscript
		= bitcoin_redeem_2of2(lnchn,
				      &lnchn->local.commitkey,
				      &lnchn->remote.commitkey);

    set_lnchn_state(lnchn,  STATE_OPEN_WAIT_FOR_ANCHORPKT, __func__, true);
    if (db_commit_transaction(lnchn) != NULL)
        return false;

    //lite_msg_open

    return true;

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
}

bool lnchn_open_local(struct LNchannel *lnchn, const struct pubkey *chnid) {

    lnchn->id = tal_dup(lnchn, struct pubkey, chnid);
    lnchn->local.commit_fee_rate = desired_commit_feerate(lnchn->dstate);
    log_debug(lnchn->log, "Using local fee rate %"PRIu64, lnchn->local.commit_fee_rate);

    //TODO: add redeem addr option
    if (!lnchn_crypto_on(lnchn, NULL)) {           
        return false;
    }

	db_start_transaction(lnchn);
	db_create_lnchn(lnchn);

	if (db_commit_transaction(lnchn) != NULL) {
		lnchn_database_err(lnchn);
        return false;
	}

	//lnchn->anchor.min_depth = get_block_height(lnchn->dstate->topology);


    return true;

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
