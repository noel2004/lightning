#ifndef LIGHTNING_LNCHANNEL_FEECHANGE_H
#define LIGHTNING_LNCHANNEL_FEECHANGE_H
#include "config.h"
#include "channel.h"

struct feechange {
	/* the side */
	enum side side;
	/* The rate. */
	u64 fee_rate;
    /* Start effect at */
    u64 commit_num;
};


#endif /* LIGHTNING_LNCHANNEL_FEECHANGE_H */
