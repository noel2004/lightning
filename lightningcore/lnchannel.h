#ifndef LIGHTNING_CORE_LNCHANNEL_H
#define LIGHTNING_CORE_LNCHANNEL_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "bitcoin/privkey.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/address.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
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
struct txowatch;

struct LNchannel *new_LNChannel(struct lightningd_state *dstate,
		      struct log *log);

bool lnchn_open_local(struct LNchannel *lnchn, const struct pubkey *chnid);

struct LNchannel_config
{
    struct rel_locktime delay;
    u32    min_depth;
    u64    initial_fee_rate;
};

bool lnchn_notify_open_remote(struct LNchannel *lnchn, 
    const struct pubkey *chnid,                /*if replay from remote, this is NULL*/
    const struct LNchannel_config *nego_config,/*if replay from remote, this is NULL*/
    const struct sha256 *revocation_hash[2], /*this and next*/
    const struct pubkey *remote_key[2] /*commit key and final key*/
);

bool lnchn_notify_open_confirmed(struct LNchannel *lnchn);


/* Whenever we send a signature, remember the txid -> commit_num mapping */
void lnchn_add_their_commit(struct LNchannel *chn,
			   const struct sha256_double *txid, u64 commit_num);

/* Allocate a new commit_info struct. */
struct commit_info *new_commit_info(const tal_t *ctx, u64 commit_num);

/* Freeing removes from map, too */
struct htlc *lnchn_new_htlc(struct LNchannel *chn,
			   u64 msatoshi,
			   const struct sha256 *rhash,
			   u32 expiry, u32 src_expiry, /* 0 if no source*/
			   enum htlc_state state);

const char *command_htlc_add(struct LNchannel *chn, u64 msatoshi,
			     unsigned int expiry,
			     const struct sha256 *rhash,
			     struct htlc *src,
			     const u8 *route,
			     enum fail_error *error_code,
			     struct htlc **htlc);

/* Peer has an issue, breakdown and fail. */
void lnchn_fail(struct LNchannel *chn, const char *caller);

//void peer_watch_anchor(struct LNchannel *chn, int depth);

struct bitcoin_tx *lnchn_create_close_tx(const tal_t *ctx,
					struct LNchannel *chn, u64 fee);

u32 get_peer_min_block(struct lightningd_state *dstate);

void debug_dump_lnchn(struct LNchannel *chn);

/*check outsourcing pending, should not closed or you may lost something...*/
bool lnchn_has_pending_outsourcing(struct LNchannel *chn);

enum outsourcing_deliver{
    OUTSOURCING_DELIVER_DONE,
    OUTSOURCING_DELIVER_FAILED,
    OUTSOURCING_DELIVER_CONFIRMED,
};

/* watch message, incoming struct MUST be allocated as children of lnchn ...*/
void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct txowatch *txo);

void lnchn_notify_tx_delivered(struct LNchannel *chn, const struct bitcoin_tx *tx,
    enum outsourcing_deliver ret, const struct sha256_double *taskid);

void cleanup_lnchn(struct lightningd_state *dstate, struct LNchannel *chn);

#endif /* LIGHTNING_CORE_LNCHANNEL_H */