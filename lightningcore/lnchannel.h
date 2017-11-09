#ifndef LIGHTNING_CORE_LNCHANNEL_H
#define LIGHTNING_CORE_LNCHANNEL_H
#include "config.h"
#include "include/lnchannel_struct.h"
#include "state.h"
#include <stdbool.h>
#include <ccan/short_types/short_types.h>

struct log;
struct lightningd_state;
struct LNchannel;
struct htlc;
struct bitcoin_tx;
struct txowatch;

struct LNchannel *new_LNChannel(struct lightningd_state *dstate,
		      struct log *log);

/* call on every channel after DB is loaded*/
void reopen_LNChannel(struct LNchannel *lnchn);

int         lnchn_u8arr_size(const unsigned char* str);
struct      msg_htlc_entry* lnchn_htlc_entry_create(const struct msg_htlc_entry*, unsigned int size, void *tal_ctx);

void        lnchn_object_release(const void *);

const struct pubkey* lnchn_channel_pubkey(const struct LNchannel*);
void               lnchn_channel_commits(const struct LNchannel*, const struct sha256_double*[3]);
const struct htlc* lnchn_channel_htlc(const struct LNchannel*, const struct sha256*);
int                lnchn_channel_state(const struct LNchannel*);
const struct sha256_double* lnchn_channel_anchor_txid(struct LNchannel *lnchn);

typedef enum LNchannelPart_e
{
    LNchn_copy_trivial = 0,
    LNchn_copy_anchor = 1,
    LNchn_copy_ourcommit = 2,
    LNchn_copy_theircommit = 4,
    LNchn_copy_closing = 8,
    LNchn_copy_htlcs = 16, /*not implemeted yet*/
    LNchn_copy_all = LNchn_copy_closing * 2 - 1,
} LNchannelPart;

struct LNchannel* lnchn_channel_copy(const struct LNchannel*, unsigned int copy_mask, void *tal_ctx);
void   lnchn_channel_update(struct LNchannel*, const struct LNchannel*, unsigned int copy_mask);

struct htlc* lnchn_htlc_copy(const struct htlc*, void *tal_ctx);
/*take API from htlc.h*/
int         lnchn_htlc_route_is_upstream(const struct htlc *h);

bool lnchn_open_local(struct LNchannel *lnchn, const struct pubkey *chnid);

/* anchor_tx must be created under lnchn ctx and not released by caller */
bool lnchn_open_anchor(struct LNchannel *lnchn, const struct bitcoin_tx *anchor_tx);

bool lnchn_add_htlc(struct LNchannel *chn, u64 msatoshi,
    unsigned int expiry,
    const struct sha256 *rhash,
    const u8 route,
    enum fail_error *error_code);

bool lnchn_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash);

bool lnchn_do_commit(struct LNchannel *chn);

bool lnchn_resolve_htlc(struct LNchannel *lnchn, const struct sha256 *rhash, 
    const struct preimage *r, enum fail_error *error_code);



//if state is less than first commit, this is safe to redeem anchord txid
//if force is false, only return valid txid for possible state and chain depth
const struct sha256_double* lnchn_get_anchor_txid(struct LNchannel *lnchn, bool force);

enum state  lnchn_get_state(struct LNchannel *lnchn);

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

bool lnchn_notify_open_remote(struct LNchannel *lnchn, 
    const struct pubkey *chnid,                /*if replay from remote, this is NULL*/
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash,      /*first hash*/
    const struct pubkey *remote_key[2] /*commit key and final key*/
);

bool lnchn_notify_anchor(struct LNchannel *lnchn, 
    const struct sha256_double *txid,
    unsigned int index,
    unsigned long long amount,
    const struct sha256 *revocation_hash
);

bool lnchn_notify_first_commit(struct LNchannel *lnchn,
    const struct sha256 *revocation_hash,
    const struct ecdsa_signature_ *sig
);

bool lnchn_notify_commit(struct LNchannel *lnchn, 
    u64 commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    u32 num_htlc_entry,
    const struct msg_htlc_entry *htlc_entry
);

bool lnchn_notify_remote_commit(struct LNchannel *lnchn,
    u64 commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    const struct sha256 *revocation_image
);

bool lnchn_notify_revo_commit(struct LNchannel *lnchn,
    u64 commit_num,
    const struct sha256 *revocation_image
);

bool lnchn_notify_commit_done(struct LNchannel *lnchn);

/* Peer has an issue, breakdown and fail. */
void lnchn_fail(struct LNchannel *chn, const char *caller);

void cleanup_lnchn(struct lightningd_state *dstate, struct LNchannel *chn);

//void peer_watch_anchor(struct LNchannel *chn, int depth);

void debug_dump_lnchn(struct LNchannel *chn);

/*check outsourcing pending, should not closed or you may lost something...*/
bool lnchn_has_pending_outsourcing(struct LNchannel *chn);

/* watch message, incoming tx struct MUST be allocated as children of lnchn ...*/

/* if handling normally, it call lnchn_resolve_htlc*/
void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo,
    const struct bitcoin_tx *tx, const struct sha256_double *taskid,
    const struct sha256 *rhash);

void lnchn_notify_tx_delivered(struct LNchannel *chn, const struct bitcoin_tx *tx,
    enum outsourcing_deliver ret, const struct sha256_double *taskid);


#endif /* LIGHTNING_CORE_LNCHANNEL_H */