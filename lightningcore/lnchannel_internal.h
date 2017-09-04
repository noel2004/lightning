/* This header holds structure definitions for struct peer, which must
 * not be exposed to ../lightningd/ */
#ifndef LIGHTNING_CORE_LNCHANNEL_INTERNAL_H
#define LIGHTNING_CORE_LNCHANNEL_INTERNAL_H
#include "config.h"
#include "btcnetwork/c/chaintopology.h"
#include "btcnetwork/c/watch.h"
#include "lightninglite/c/manager.h"
#include "lightninglite/c/message.h"

struct anchor_input {
	struct sha256_double txid;
	unsigned int index;
	/* Amount of input (satoshis), and output (satoshis) */
	u64 in_amount, out_amount;
	/* Wallet entry to use to spend. */
	struct pubkey walletkey;
};

/* Information we remember for their commitment txs which we signed.
 *
 * Given the commit_num, we can use shachain to derive the revocation preimage
 * (if we've received it yet: we might have not, for the last).
 */
struct their_commit {
	struct list_node list;

	struct sha256_double txid;
	u64 commit_num;
};

struct commit_info {
	/* Commit number (0 == from open) */
	u64 commit_num;
	/* Revocation hash. */
	struct sha256 revocation_hash;
	/* Commit tx & txid */
	struct bitcoin_tx *tx;
	struct sha256_double txid;
	/* Channel state for this tx. */
	struct channel_state *cstate;
	/* Other side's signature for last commit tx (if known) */
	ecdsa_signature *sig;
	/* Order which commit was sent (theirs) / revocation was sent (ours) */
	s64 order;
};

struct LNChannel_visible_state {
	/* Is this side funding the channel? */
	bool offer_anchor;
	/* Key for commitment tx inputs, then key for commitment tx outputs */
	struct pubkey commitkey, finalkey;
	/* How long to they want the other's outputs locked (blocks) */
	struct rel_locktime locktime;
	/* Minimum depth of anchor before channel usable. */
	unsigned int mindepth;
	/* Commitment fee they're offering (satoshi). */
	u64 commit_fee_rate;
	/* Revocation hash for next commit tx. */
	struct sha256 next_revocation_hash;
	/* Commit txs: last one is current. */
	struct commit_info *commit;

	/* cstate to generate next commitment tx. */
	struct channel_state *staging_cstate;
};

struct LNChannel_rt
{
    /* last commit which is not revoked yet */
    struct commit_info *their_last_commit;

    /* counter for outsourcing callback */
    u64 outsourcing_counter;

    /* internal_watch_xxx use this to generate callback */
    void(*outsourcing_f)(struct LNchannel *, enum outsourcing_result, u64);

    bool outsourcing_lock;

    struct msg_htlc_entry *commit_msg_cache;

    u8* temp_errormsg;
};

struct LNchannel {
	/* dstate->peers list */
	struct list_node list;

	/* State in state machine. */
	enum state state;

    /* the block height which state is set*/
    u32 state_height;

	/* Global state. */
	struct lightningd_state *dstate;

	/* Their ID. */
	struct pubkey *id;

	/* Order counter for transmission of revocations/commitments. */
	//s64 order_counter;

	/* Their commitments we have signed (which could appear on chain). */
	struct list_head their_commits;

	/* Number of commitment signatures we've received. */
	u64 their_commitsigs;

	/* Anchor tx output */
	struct {
		struct sha256_double txid;
		unsigned int index;
		u64 satoshis;
		u8 *witnessscript;

		/* Minimum possible depth for anchor */
		unsigned int min_depth;

		/* If we're creating anchor, this tells us where to source it */
		struct anchor_input *input;

		/* If we created it, we keep entire tx. */
		const struct bitcoin_tx *tx;

		/* Depth to trigger anchor if still opening, or -1. */
		int ok_depth;

		/* Did we create anchor? */
		bool ours;
	} anchor;

	struct {
		/* Their signature for our current commit sig. */
		ecdsa_signature theirsig;
		/* The watch we have on a live commit tx. */
		//struct txwatch *watch;
	} cur_commit;

	///* Counter to make unique HTLC ids. */
	//u64 htlc_id_counter;

	/* Mutual close info. */
	struct {
		/* Our last suggested closing fee. */
		u64 our_fee;
		/* If they've offered a signature, these are set: */
		ecdsa_signature *their_sig;
		/* If their_sig is non-NULL, this is the fee. */
		u64 their_fee;
		/* scriptPubKey we/they want for closing. */
		u8 *our_script, *their_script;
		/* Last sent (in case we need to retransmit) */
		s64 shutdown_order, closing_order;
		/* How many closing sigs have we receieved? */
		u32 sigs_in;
	} closing;

	/* If we're closing on-chain */
	struct {
		/* Everything (watches, resolved[], etc) tal'ed off this:
		 * The commit which spends the anchor tx. */
		const struct bitcoin_tx *tx;
		struct sha256_double txid;

		/* If >= 0, indicates which txout is to us and to them. */
		int to_us_idx, to_them_idx;
		/* Maps what txouts are HTLCs (NULL implies to_us/them_idx). */
		struct htlc **htlcs;
		/* The tx which resolves each txout. */
		const struct bitcoin_tx **resolved;
	} onchain;

    struct bitcoin_address redeem_addr;

	/* All HTLCs. */
	struct htlc_map htlcs;

	//struct feechange *feechanges[2];

	/* What happened. */
	struct log *log;

    /* Tell detail for a notify failure*/
    char* notify_fail_reason;

	/* Things we're watching for (see watches.c) */
	//struct list_head watches;

	/* Timeout for collecting changes before sending commit. */
	struct oneshot *commit_timer;

	/* Private keys for dealing with this peer. */
	struct channel_secrets *secrets;

	/* For testing. */
	bool fake_close;
	bool output_enabled;

	/* Stuff we have in common. */
	struct LNChannel_visible_state local, remote;

	/* this is where we will store their revocation preimages*/
	struct shachain their_preimages;

    struct LNChannel_rt rt;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;
};

//many internal api and helpers ...

/* Allocate a new commit_info struct. */
struct commit_info *internal_new_commit_info(const tal_t *ctx, u64 commit_num);

/* MUST call after the chn is completly initialized! Freeing removes from map, too */
struct htlc *internal_new_htlc(struct LNchannel *chn,
			   u64 msatoshi,
			   const struct sha256 *rhash,
			   u32 expiry, u32 src_expiry, /* 0 if no source*/
			   enum htlc_state state);

void internal_htlc_update_deadline(struct LNchannel *lnchn, struct htlc *h, const struct htlc *srch);

void internal_lnchn_breakdown(struct LNchannel *lnchn);

void internal_lnchn_temp_breakdown(struct LNchannel *lnchn, const char* reason);

void internal_lnchn_fail_on_notify(struct LNchannel *lnchn, const char* msg, ...);

void internal_set_lnchn_state(struct LNchannel *lnchn, enum state newstate,
    const char *caller, bool db_commit);

void internal_update_htlc_watch(struct LNchannel *chn, 
                 const struct sha256 *rhash, struct txowatch* txo);

void internal_fail_own_htlc(struct LNchannel *lnchn, struct htlc *htlc);

void internal_openphase_retry_msg(struct LNchannel *lnchn);

void internal_commitphase_retry_msg(struct LNchannel *lnchn);

void internal_outsourcing_for_committing(struct LNchannel *chn, enum side side);

void internal_outsourcing_for_commit(struct LNchannel *chn, enum side side);

static bool outputscript_eq(const struct bitcoin_tx_output *out,
    size_t i, const u8 *script)
{
    if (tal_count(out[i].script) != tal_count(script))
        return false;
    return memcmp(out[i].script, script, tal_count(script)) == 0;
}

static u64 desired_commit_feerate(struct lightningd_state *dstate)
{
    return get_feerate(dstate->topology) * dstate->config.commitment_fee_percent / 100;
}

#endif /* LIGHTNING_CORE_LNCHANNEL_INTERNAL_H */
