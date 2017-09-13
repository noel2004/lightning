#ifndef LIGHTNING_CORE_LNCHANNEL_H
#define LIGHTNING_CORE_LNCHANNEL_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "bitcoin/privkey.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/address.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/preimage.h"
#include "failure.h"
#include "feechange.h"
#include "htlc.h"
#include "state.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <ccan/time/time.h>

struct log;
struct lightningd_state;
struct LNchannel;
struct bitcoin_tx;
struct txowatch;
struct sha256_double;
struct msg_htlc_entry;

struct LNchannel *new_LNChannel(struct lightningd_state *dstate,
		      struct log *log);

/* call on every channel after DB is loaded*/
void reopen_LNChannel(struct LNchannel *lnchn);

bool lnchn_open_local(struct LNchannel *lnchn, const struct pubkey *chnid);

bool lnchn_open_anchor(struct LNchannel *lnchn, const struct bitcoin_tx *anchor_tx);

bool lnchn_add_htlc(struct LNchannel *chn, u64 msatoshi,
    unsigned int expiry,
    const struct sha256 *rhash,
    const u8 route,
    enum fail_error *error_code);

bool lnchn_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash);

bool lnchn_do_commit(struct LNchannel *chn, 
    const struct sha256 *next_revocation);

bool lnchn_resolve_htlc(struct LNchannel *lnchn, const struct sha256 *rhash, 
    const struct preimage *r, enum fail_error *error_code);



//if state is less than first commit, this is safe to redeem anchord txid
//if force is false, only return valid txid for possible state and chain depth
const struct sha256_double* lnchn_get_anchor_txid(struct LNchannel *lnchn, bool force);

enum state  lnchn_get_state(struct LNchannel *lnchn);

struct LNchannel_config
{
    struct rel_locktime delay;
    u32    min_depth;
    u64    initial_fee_rate;
    u64    purpose_satoshi;
};

void lnchn_negotiate_from_remote(struct LNchannel *lnchn);

/*
    process of commiting:
  * negotation: which side and other parameters (currently only feerate)
  * A send remote commit
  * B reply remote commit and revoking-hash
  * A send revoking-hash

  * channel state is persisted to "COMMITING" when commit is sent
  * for the restored channel, always start with a re-sent commit
  * a restored channel may stay in COMMITE state (while another side
  * is COMMITING), in this case, commit message from another side
  * is rejected and re-negotation is required. 
*/

/* 
    when channel is under COMMITING state, help to restore 
    all required negotation data and rebuild the committing process

    there is three possible state for restored-channel:

    invoked side ----- received side ---------- action
    COMMITE            COMMITE                  previous negotation is lost, 
                                                can start a new one
    COMMITING          COMMITE                  COMMITING side reject new negotation, and
                                                send message to restore the processing one
                                                COMMITE side reject the first re-sent commit
                                                message and wait for a new negotation for
                                                the processing one
    COMMITING          COMMITING                both side simply re-send their commit
*/
void lnchn_restore_commit_state(struct LNchannel *lnchn);

bool lnchn_notify_open_remote(struct LNchannel *lnchn, 
    const struct pubkey *chnid,                /*if replay from remote, this is NULL*/
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash,      /*first hash*/
    const struct pubkey *remote_key[2] /*commit key and final key*/
);

bool lnchn_notify_anchor(struct LNchannel *lnchn, const struct pubkey *chnid,
    const struct sha256_double *txid,
    unsigned int index,
    unsigned long long amount
);

bool lnchn_notify_commit(struct LNchannel *lnchn, 
    u64 commit_num,
    const ecdsa_signature *sig,
    const struct sha256 *next_revocation,
    u32 num_htlc_entry,
    const struct msg_htlc_entry *htlc_entry
);

bool lnchn_notify_remote_commit(struct LNchannel *lnchn,
    u64 commit_num,
    const ecdsa_signature *sig,
    const struct preimage *revocation_image
);

bool lnchn_notify_revo_commit(struct LNchannel *lnchn,
    u64 commit_num,
    const struct preimage *revocation_image
);

bool lnchn_notify_commit_done(struct LNchannel *lnchn, u64 commit_num);

/* Peer has an issue, breakdown and fail. */
void lnchn_fail(struct LNchannel *chn, const char *caller);

void cleanup_lnchn(struct lightningd_state *dstate, struct LNchannel *chn);

//void peer_watch_anchor(struct LNchannel *chn, int depth);

void debug_dump_lnchn(struct LNchannel *chn);

/*check outsourcing pending, should not closed or you may lost something...*/
bool lnchn_has_pending_outsourcing(struct LNchannel *chn);

enum outsourcing_deliver{
    OUTSOURCING_DELIVER_DONE,
    OUTSOURCING_DELIVER_FAILED,
    OUTSOURCING_DELIVER_CONFIRMED,
};

/* watch message, incoming tx struct MUST be allocated as children of lnchn ...*/

/* if handling normally, it call lnchn_resolve_htlc*/
void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo,
    const struct bitcoin_tx *tx, const struct sha256_double *taskid,
    const struct sha256 *rhash);

void lnchn_notify_tx_delivered(struct LNchannel *chn, const struct bitcoin_tx *tx,
    enum outsourcing_deliver ret, const struct sha256_double *taskid);


#endif /* LIGHTNING_CORE_LNCHANNEL_H */