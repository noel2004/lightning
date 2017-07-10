/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "utils/utils.h"
#include <ccan/cast/cast.h>
#include <ccan/str/hex/hex.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>

/* If ctx is non-NULL, and is freed before we return, we don't call process() */
static void
start_bitcoin_cli(struct bitcoind *bitcoind,
		  const tal_t *ctx,
		  void (*process)(struct bitcoin_cli *),
		  bool nonzero_exit_ok,
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{

}

void bitcoind_estimate_fee_(struct bitcoind *bitcoind,
			    void (*cb)(struct bitcoind *bitcoind,
				       u64, void *),
			    void *arg)
{
}

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    int exitstatus, const char *msg, void *),
			 void *arg)
{

}

void bitcoind_get_chaintip_(struct bitcoind *bitcoind,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct sha256_double *tipid,
				       void *arg),
			    void *arg)
{

}


void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct sha256_double *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk,
				      void *arg),
			   void *arg)
{
}


void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			      void (*cb)(struct bitcoind *bitcoind,
					 u32 blockcount,
					 void *arg),
			      void *arg)
{

}

void bitcoind_getblockhash_(struct bitcoind *bitcoind,
			    u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct sha256_double *blkid,
				       void *arg),
			    void *arg)
{

}

