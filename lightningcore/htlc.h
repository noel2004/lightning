#ifndef LIGHTNING_CORE_HTLC_H
#define LIGHTNING_CORE_HTLC_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "pseudorand.h"
#include <assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>

enum htlc_state {
    /* When we add a new htlc, it goes in this order. */
    SENT_ADD_HTLC,
    SENT_ADD_COMMIT,
    RCVD_ADD_REVOCATION,
    RCVD_ADD_ACK_COMMIT,
    SENT_ADD_ACK_REVOCATION,

    /* When they remove an htlc, it goes from SENT_ADD_ACK_REVOCATION: */
    RCVD_REMOVE_HTLC,
    RCVD_REMOVE_COMMIT,
    SENT_REMOVE_REVOCATION,
    SENT_REMOVE_ACK_COMMIT,
    RCVD_REMOVE_ACK_REVOCATION,

    /* When they add a new htlc, it goes in this order. */
    RCVD_ADD_HTLC,
    RCVD_ADD_COMMIT,
    SENT_ADD_REVOCATION,
    SENT_ADD_ACK_COMMIT,
    RCVD_ADD_ACK_REVOCATION,

    /* When we remove an htlc, it goes from RCVD_ADD_ACK_REVOCATION: */
    SENT_REMOVE_HTLC,
    SENT_REMOVE_COMMIT,
    RCVD_REMOVE_REVOCATION,
    RCVD_REMOVE_ACK_COMMIT,
    SENT_REMOVE_ACK_REVOCATION,

    HTLC_STATE_INVALID
};

enum side {
	LOCAL,
	REMOTE,
	NUM_SIDES
};

/* What are we doing: adding or removing? */
#define HTLC_ADDING			0x400
#define HTLC_REMOVING			0x800

/* Uncommitted change is pending */
#define HTLC_F_PENDING			0x01
/* HTLC is in commit_tx */
#define HTLC_F_COMMITTED		0x02
/* We have revoked the previous commit_tx */
#define HTLC_F_REVOKED			0x04
/* We offered it it. */
#define HTLC_F_OWNER			0x08
/* HTLC was ever in a commit_tx */
#define HTLC_F_WAS_COMMITTED		0x10

/* Each of the above flags applies to both sides */
#define HTLC_FLAG(side,flag)		((flag) << ((side) * 5))

#define HTLC_REMOTE_F_PENDING		HTLC_FLAG(REMOTE,HTLC_F_PENDING)
#define HTLC_REMOTE_F_COMMITTED		HTLC_FLAG(REMOTE,HTLC_F_COMMITTED)
#define HTLC_REMOTE_F_REVOKED		HTLC_FLAG(REMOTE,HTLC_F_REVOKED)
#define HTLC_REMOTE_F_OWNER		HTLC_FLAG(REMOTE,HTLC_F_OWNER)
#define HTLC_REMOTE_F_WAS_COMMITTED	HTLC_FLAG(REMOTE,HTLC_F_WAS_COMMITTED)

#define HTLC_LOCAL_F_PENDING		HTLC_FLAG(LOCAL,HTLC_F_PENDING)
#define HTLC_LOCAL_F_COMMITTED		HTLC_FLAG(LOCAL,HTLC_F_COMMITTED)
#define HTLC_LOCAL_F_REVOKED		HTLC_FLAG(LOCAL,HTLC_F_REVOKED)
#define HTLC_LOCAL_F_OWNER		HTLC_FLAG(LOCAL,HTLC_F_OWNER)
#define HTLC_LOCAL_F_WAS_COMMITTED	HTLC_FLAG(LOCAL,HTLC_F_WAS_COMMITTED)

struct htlc {
    const char* channelId;
	/* Block number where we abort if it's still live (LOCAL only) */
	u32 deadline;
	/* What's the status. */
	enum htlc_state state;
	///* The unique ID for this peer and this direction (LOCAL or REMOTE) */
	//u64 id;
	/* The amount in millisatoshi. */
	u64 msatoshi;
	/* When the HTLC can no longer be redeemed. */
	struct abs_locktime expiry;
	/* The hash of the preimage which can redeem this HTLC */
	struct sha256 rhash;
	/* The preimage which hashes to rhash (if known) */
	struct preimage *r;
    const u8 *fail;
	///* FIXME: We could union these together: */
	///* Routing information sent with this HTLC. */
	//const u8 *routing;
	/* Previous HTLC (if any) which made us offer this (LOCAL only) */
	//struct htlc *src;
    //const char *src_channelid;

	/* FIXME: actually an enum onion_type */
	//u8 malformed;

    /* the "life" history of a htlc: that is, the commit number at which */
    /* it was added to the number it was resolved (commited or revoked) */
    u64 history[2];
};

const char *htlc_state_name(enum htlc_state s);
enum htlc_state htlc_state_from_name(const char *name);
void htlc_changestate(struct htlc *h,
		      enum htlc_state oldstate,
		      enum htlc_state newstate);
int htlc_state_flags(enum htlc_state state);

static inline bool htlc_has(const struct htlc *h, int flag)
{
	return htlc_state_flags(h->state) & flag;
}

static inline enum side htlc_state_owner(enum htlc_state state)
{
	if (state < RCVD_ADD_HTLC) {
		assert((htlc_state_flags(state)
			& (HTLC_REMOTE_F_OWNER|HTLC_LOCAL_F_OWNER))
		       == HTLC_LOCAL_F_OWNER);
		return LOCAL;
	} else {
		assert((htlc_state_flags(state)
			& (HTLC_REMOTE_F_OWNER|HTLC_LOCAL_F_OWNER))
		       == HTLC_REMOTE_F_OWNER);
		return REMOTE;
	}
}

static inline enum side htlc_owner(const struct htlc *h)
{
	return htlc_state_owner(h->state);
}

void htlc_undostate(struct htlc *h,
		    enum htlc_state oldstate, enum htlc_state newstate);

/* htlc_map: ID -> htlc mapping. */
static inline const struct sha256* htlc_key(const struct htlc *h)
{
	return &h->rhash;
}
static inline bool htlc_cmp(const struct htlc *h, const struct sha256* hash)
{
    return memcmp(h->rhash.u.u8, hash->u.u8, sizeof(hash->u.u8)) == 0;
}
static inline size_t htlc_hash(const struct sha256* hash)
{
    size_t ret = 0;
    int i;

    for (i = 0; i < sizeof(hash->u.u32) / sizeof(hash->u.u32[0]); ++i)
    {
        ret += hash->u.u32[i];
    }

    return ret;
}

#if !HAVE_TYPEOF
#undef HTABLE_KTYPE
#define HTABLE_KTYPE(keyof, type) struct sha256*
#endif

HTABLE_DEFINE_TYPE(struct htlc, htlc_key, htlc_hash, htlc_cmp, htlc_map);


static inline struct htlc *htlc_get(struct htlc_map *htlcs, struct sha256* hash, enum side owner)
{
	struct htlc *h;
	struct htlc_map_iter it;

	for (h = htlc_map_getfirst(htlcs, hash, &it);
	     h;
	     h = htlc_map_getnext(htlcs, hash, &it)) {
		if (htlc_cmp(h, hash) && htlc_has(h, HTLC_FLAG(owner,HTLC_F_OWNER)))
			return h;
	}
	return NULL;
}

static inline size_t htlc_map_count(const struct htlc_map *htlcs)
{
	return htlcs->raw.elems;
}

/* FIXME: Move these out of the hash! */
static inline bool htlc_is_dead(const struct htlc *htlc)
{
	return htlc->state == RCVD_REMOVE_ACK_REVOCATION
		|| htlc->state == SENT_REMOVE_ACK_REVOCATION;
}


static inline const char *side_to_str(enum side side)
{
	switch (side) {
	case LOCAL: return "LOCAL";
	case REMOTE: return "REMOTE";
	case NUM_SIDES: break;
	}
	abort();
}

static inline enum side str_to_side(const char *str)
{
	if (streq(str, "LOCAL"))
		return LOCAL;
	assert(streq(str, "REMOTE"));
	return REMOTE;
}
#endif /* LIGHTNING_CORE_HTLC_H */
