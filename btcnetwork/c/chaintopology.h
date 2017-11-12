#ifndef LIGHTNING_BTCNETWORK_CHAINTOPOLOGY_C_INTERFACE_H
#define LIGHTNING_BTCNETWORK_CHAINTOPOLOGY_C_INTERFACE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct sha256_double;
struct chain_topology;

/* init chain_topology and outsourcing service, require other lite modules */
void    btcnetwork_init(struct lightningd_state* state);
void    btcnetwork_release(struct lightningd_state* state);

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* This is the number of blocks which would have to be mined to invalidate
 * the tx. */
size_t get_tx_depth(const struct chain_topology *topo,
		    const struct sha256_double *txid);

/* Get the mediantime of the block including this tx (must be one!) */
u32 get_tx_mediantime(const struct chain_topology *topo,
		      const struct sha256_double *txid);

/* Get mediantime of the tip; if more than one, pick greatest time. */
u32 get_tip_mediantime(const struct chain_topology *topo);

/* Get highest block number. */
u32 get_block_height(const struct chain_topology *topo);

/* Get fee rate. */
u64 get_feerate(const struct chain_topology *topo);

/* Broadcast a single tx, and rebroadcast as reqd (copies tx).
 * If failed is non-NULL, call that and don't rebroadcast. */
//void broadcast_tx(struct chain_topology *topo,
//		  struct peer *peer, const struct bitcoin_tx *tx,
//		  void (*failed)(struct peer *peer,
//				 int exitstatus,
//				 const char *err));

//struct chain_topology *new_topology(const tal_t *ctx, struct log *log);
//void setup_topology(struct chain_topology *topology, struct bitcoind *bitcoind,
//		    struct timers *timers,
//		    struct timerel poll_time, u32 first_peer_block);

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo, const struct sha256_double *txid);

//void notify_new_block(struct chain_topology *topo, unsigned int height);


#endif /* LIGHTNING_BTCNETWORK_CHAINTOPOLOGY_C_INTERFACE_H */
