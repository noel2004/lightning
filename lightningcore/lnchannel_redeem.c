#include "db.h"
#include "log.h"
#include "lnchannel.h"
#include "lnchannel_internal.h"
#include "permute_tx.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "find_p2sh_out.h"
#include "output_to_htlc.h"
#include "pseudorand.h"
#include "remove_dust.h"
#include "secrets.h"
#include "btcnetwork/c/chaintopology.h"
#include "btcnetwork/c/watch.h"
#include "utils/utils.h"
#include "utils/sodium/randombytes.h"
#include <bitcoin/base58.h>
#include <bitcoin/address.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>


/* Create a HTLC fulfill transaction for onchain.tx[out_num]. */
static const struct bitcoin_tx *htlc_fulfill_tx(const struct LNchannel *lnchn,
						unsigned int out_num)
{
	struct bitcoin_tx *tx = bitcoin_tx(lnchn, 1, 1);
	const struct htlc *htlc = lnchn->onchain.htlcs[out_num];
	const u8 *wscript = lnchn->onchain.wscripts[out_num];
	ecdsa_signature sig;
	u64 fee, satoshis;

	assert(htlc->r);

	tx->input[0].index = out_num;
	tx->input[0].txid = lnchn->onchain.txid;
	satoshis = htlc->msatoshi / 1000;
	tx->input[0].amount = tal_dup(tx->input, u64, &satoshis);
	tx->input[0].sequence_number = bitcoin_nsequence(&lnchn->remote.locktime);

	/* Using a new output address here would be useless: they can tell
	 * it's their HTLC, and that we collected it via rval. */
    tx->output[0].script = scriptpubkey_p2pkh(tx, &lnchn->redeem_addr);

	log_debug(lnchn->log, "Pre-witness txlen = %zu\n",
		  measure_tx_cost(tx) / 4);

	assert(measure_tx_cost(tx) == 83 * 4);

	/* Witness length can vary, due to DER encoding of sigs, but we
	 * use 539 from an example run. */
	fee = fee_by_feerate(83 + 539 / 4, get_feerate(lnchn->dstate->topology));

	/* FIXME: Fail gracefully in these cases (not worth collecting) */
	if (fee > satoshis || is_dust(satoshis - fee))
		fatal("HTLC fulfill amount of %"PRIu64" won't cover fee %"PRIu64,
		      satoshis, fee);

	tx->output[0].amount = satoshis - fee;

	lnchn_sign_htlc_fulfill(lnchn, tx, wscript, &sig);

	tx->input[0].witness = bitcoin_witness_htlc(tx,
						    htlc->r, &sig, wscript);

	log_debug(lnchn->log, "tx cost for htlc fulfill tx: %zu",
		  measure_tx_cost(tx));

	return tx;
}

void lnchn_notify_txo_delivered(struct LNchannel *chn, const struct bitcoin_tx *tx)
{

}

void lnchn_notify_tx_delivered(struct LNchannel *chn, const struct bitcoin_tx *tx)
{

}