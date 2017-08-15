//#include "db.h"
#include "feechange.h"
#include "log.h"
#include "lnchannel.h"
#include "lnchannel_internal.h"
#include <ccan/array_size/array_size.h>
#include <inttypes.h>

struct {
    enum feechange_state v;
    const char *name;
} enum_feechange_state_names[] = {
    { SENT_FEECHANGE, "SENT_FEECHANGE" },
    { SENT_FEECHANGE_COMMIT, "SENT_FEECHANGE_COMMIT" },
    { RCVD_FEECHANGE_REVOCATION, "RCVD_FEECHANGE_REVOCATION" },
    { RCVD_FEECHANGE_ACK_COMMIT, "RCVD_FEECHANGE_ACK_COMMIT" },
    { SENT_FEECHANGE_ACK_REVOCATION, "SENT_FEECHANGE_ACK_REVOCATION" },
    { RCVD_FEECHANGE, "RCVD_FEECHANGE" },
    { RCVD_FEECHANGE_COMMIT, "RCVD_FEECHANGE_COMMIT" },
    { SENT_FEECHANGE_REVOCATION, "SENT_FEECHANGE_REVOCATION" },
    { SENT_FEECHANGE_ACK_COMMIT, "SENT_FEECHANGE_ACK_COMMIT" },
    { RCVD_FEECHANGE_ACK_REVOCATION, "RCVD_FEECHANGE_ACK_REVOCATION" },
    { FEECHANGE_STATE_INVALID, "FEECHANGE_STATE_INVALID" },
    { 0, NULL } };

/* This is the HTLC-like flags for each state. */
static const int per_state_bits[] = {
	[SENT_FEECHANGE] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_PENDING,

	[SENT_FEECHANGE_COMMIT] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_FEECHANGE_REVOCATION] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_PENDING
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_FEECHANGE_ACK_COMMIT] = HTLC_ADDING + HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[SENT_FEECHANGE_ACK_REVOCATION] = HTLC_LOCAL_F_OWNER
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_FEECHANGE] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_PENDING,

	[RCVD_FEECHANGE_COMMIT] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED,

	[SENT_FEECHANGE_REVOCATION] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_PENDING
	+ HTLC_LOCAL_F_WAS_COMMITTED,

	[SENT_FEECHANGE_ACK_COMMIT] = HTLC_ADDING + HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,

	[RCVD_FEECHANGE_ACK_REVOCATION] = HTLC_REMOTE_F_OWNER
	+ HTLC_LOCAL_F_COMMITTED
	+ HTLC_LOCAL_F_REVOKED
	+ HTLC_REMOTE_F_COMMITTED
	+ HTLC_REMOTE_F_REVOKED
	+ HTLC_LOCAL_F_WAS_COMMITTED
	+ HTLC_REMOTE_F_WAS_COMMITTED,
};

int feechange_state_flags(enum feechange_state state)
{
	assert(state < ARRAY_SIZE(per_state_bits));
	assert(per_state_bits[state]);
	return per_state_bits[state];
}

const char *feechange_state_name(enum feechange_state s)
{
	size_t i;

	for (i = 0; enum_feechange_state_names[i].name; i++)
		if (enum_feechange_state_names[i].v == s)
			return enum_feechange_state_names[i].name;
	return "unknown";
}

enum feechange_state feechange_state_from_name(const char *name)
{
	size_t i;

	for (i = 0; enum_feechange_state_names[i].name; i++)
		if (streq(enum_feechange_state_names[i].name, name))
			return enum_feechange_state_names[i].v;
	return FEECHANGE_STATE_INVALID;
}

struct feechange *new_feechange(struct LNchannel *lnchn,
				u64 fee_rate,
				enum feechange_state state)
{
	struct feechange *f = tal(lnchn, struct feechange);
	f->state = state;
	f->fee_rate = fee_rate;

	return f;
}

void feechange_changestate(struct LNchannel *lnchn,
			   struct feechange *f,
			   enum feechange_state oldstate,
			   enum feechange_state newstate)
{
	log_debug(lnchn->log, "feechange: %s->%s",
		  feechange_state_name(f->state),
		  feechange_state_name(newstate));
	assert(f->state == oldstate);
	assert(lnchn->feechanges[f->state] == f);

	/* You can only go to consecutive states. */
	assert(newstate == f->state + 1);

	/* You can't change sides. */
	assert(feechange_side(f->state) == feechange_side(newstate));

	f->state = newstate;

	/* We can have multiple dead feestates, but only one in any other */
	if (!feechange_is_dead(f))
		assert(!lnchn->feechanges[f->state]);

	lnchn->feechanges[oldstate] = NULL;
	lnchn->feechanges[newstate] = f;
}
