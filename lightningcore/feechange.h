#ifndef LIGHTNING_DAEMON_FEECHANGE_H
#define LIGHTNING_DAEMON_FEECHANGE_H
#include "config.h"
#include "channel.h"

/* Like HTLCs, but only adding; we never "remove" a feechange. */
enum feechange_state {
    /* When we add a new feechange, it goes in this order. */
    SENT_FEECHANGE,
    SENT_FEECHANGE_COMMIT,
    RCVD_FEECHANGE_REVOCATION,
    RCVD_FEECHANGE_ACK_COMMIT,
    SENT_FEECHANGE_ACK_REVOCATION,

    /* When they add a new feechange, it goes in this order. */
    RCVD_FEECHANGE,
    RCVD_FEECHANGE_COMMIT,
    SENT_FEECHANGE_REVOCATION,
    SENT_FEECHANGE_ACK_COMMIT,
    RCVD_FEECHANGE_ACK_REVOCATION,

    FEECHANGE_STATE_INVALID
};

struct feechange {
	/* What's the status */
	enum feechange_state state;
	/* The rate. */
	u64 fee_rate;
};

static inline enum side feechange_side(enum feechange_state state)
{
	if (state <= SENT_FEECHANGE_ACK_REVOCATION) {
		return LOCAL;
	} else {
		assert(state < FEECHANGE_STATE_INVALID);
		return REMOTE;
	}
}

void feechange_changestate(struct LNchannel *lnchn,
			   struct feechange *feechange,
			   enum feechange_state oldstate,
			   enum feechange_state newstate);

struct feechange *new_feechange(struct LNchannel *lnchn,
				u64 fee_rate,
				enum feechange_state state);

const char *feechange_state_name(enum feechange_state s);
enum feechange_state feechange_state_from_name(const char *name);

/* HTLC-add-style bitflags for each feechange state */
int feechange_state_flags(enum feechange_state state);

static inline bool feechange_has(const struct feechange *f, int flag)
{
	return feechange_state_flags(f->state) & flag;
}

static inline bool feechange_is_dead(const struct feechange *feechange)
{
	return feechange->state == SENT_FEECHANGE_ACK_REVOCATION
		|| feechange->state == RCVD_FEECHANGE_ACK_REVOCATION;
}
#endif /* LIGHTNING_DAEMON_FEECHANGE_H */
