#ifndef LIGHTNING_STATE_TYPES_H
#define LIGHTNING_STATE_TYPES_H
#include "config.h"

enum state {
	STATE_INIT,

	/*
	 * Opening.
	 */
	STATE_OPEN_WAIT_FOR_OPENPKT,
	STATE_OPEN_WAIT_FOR_ANCHORPKT,
    STATE_OPEN_WAIT_FOR_CREATEANCHOR,
	STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT,

	/* We're waiting for depth+their complete. */
	STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE,
	/* Got their pkt_complete. */
	STATE_OPEN_WAIT_ANCHORDEPTH,
	/* Got anchor depth. */
	STATE_OPEN_WAIT_THEIRCOMPLETE,

	/*
	 * Normal state.
	 */
	STATE_NORMAL,
	STATE_NORMAL_COMMITTING,

	/*
	 * Closing (handled outside state machine).
	 */
	STATE_SHUTDOWN,
	STATE_SHUTDOWN_COMMITTING,
	STATE_MUTUAL_CLOSING,

	/* Four states to represent closing onchain (for getpeers) */
	STATE_CLOSE_ONCHAIN_CHEATED,
	STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL,
	STATE_CLOSE_ONCHAIN_OUR_UNILATERAL,
	STATE_CLOSE_ONCHAIN_MUTUAL,

	/* All closed. */
	STATE_CLOSED,

	/*
	 * Where angels fear to tread.
	 */
	/* Bad packet from them / protocol breakdown. */
	STATE_ERR_BREAKDOWN,
	/* The anchor didn't reach blockchain in reasonable time. */
	STATE_ERR_ANCHOR_TIMEOUT,
	/* We saw a tx we didn't sign. */
	STATE_ERR_INFORMATION_LEAK,
	/* We ended up in an unexpected state. */
	STATE_ERR_INTERNAL,

	STATE_MAX
};

#endif /* LIGHTNING_STATE_TYPES_H */
