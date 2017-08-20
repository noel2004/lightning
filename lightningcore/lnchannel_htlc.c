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


bool lnchn_add_htlc(struct LNchannel *chn, u64 msatoshi,
    unsigned int expiry,
    const struct sha256 *rhash,
    const u8 route,
    enum fail_error *error_code)
{
    return false;
}

static void set_htlc_rval(struct LNchannel *lnchn,
			  struct htlc *htlc, const struct preimage *rval)
{
	assert(!htlc->r);
	assert(!htlc->fail);
	htlc->r = tal_dup(htlc, struct preimage, rval);
	db_htlc_fulfilled(lnchn, htlc);
}

static void set_htlc_fail(struct LNchannel *lnchn,
			  struct htlc *htlc, const void *fail, size_t len)
{
	assert(!htlc->r);
	assert(!htlc->fail);
	htlc->fail = tal_dup_arr(htlc, u8, fail, len, 0);
	db_htlc_failed(lnchn, htlc);
}

static void route_htlc_onwards(struct LNchannel *lnchn,
			       struct htlc *htlc,
			       u64 msatoshi,
			       const u8 *pb_id,
			       const u8 *rest_of_route,
			       const struct LNchannel *only_dest)
{
	struct LNchannel *next;
	struct htlc *newhtlc;
	enum fail_error error_code;
	const char *err;

	if (!only_dest) {
		log_debug_struct(lnchn->log, "Forwarding HTLC %s",
				 struct sha256, &htlc->rhash);
		log_add(lnchn->log, " (id %"PRIu64")", htlc->id);
	}

	next = find_lnchn_by_pkhash(lnchn->dstate, pb_id);
	if (!next || !next->nc) {
		log_unusual(lnchn->log, "Can't route HTLC %"PRIu64": no %slnchn ",
			    htlc->id, next ? "ready " : "");
		if (!lnchn->dstate->dev_never_routefail)
			command_htlc_set_fail(lnchn, htlc, NOT_FOUND_404,
					      "Unknown lnchn");
		return;
	}

	if (only_dest && next != only_dest)
		return;

	/* Offered fee must be sufficient. */
	if ((s64)(htlc->msatoshi - msatoshi)
	    < connection_fee(next->nc, msatoshi)) {
		log_unusual(lnchn->log,
			    "Insufficient fee for HTLC %"PRIu64
			    ": %"PRIi64" on %"PRIu64,
			    htlc->id, htlc->msatoshi - msatoshi,
			    msatoshi);
		command_htlc_set_fail(lnchn, htlc, PAYMENT_REQUIRED_402,
				      "Insufficent fee");
		return;
	}

	log_debug_struct(lnchn->log, "HTLC forward to %s",
			 struct pubkey, next->id);

	/* This checks the HTLC itself is possible. */
	err = command_htlc_add(next, msatoshi,
			       abs_locktime_to_blocks(&htlc->expiry)
			       - next->nc->delay,
			       &htlc->rhash, htlc, rest_of_route,
			       &error_code, &newhtlc);
	if (err)
		command_htlc_set_fail(lnchn, htlc, error_code, err);
}

static void their_htlc_added(struct LNchannel *lnchn, struct htlc *htlc,
			     struct LNchannel *only_dest)
{
	struct invoice *invoice;
	struct onionpacket *packet;
	struct route_step *step = NULL;

	if (abs_locktime_is_seconds(&htlc->expiry)) {
		log_unusual(lnchn->log, "HTLC %"PRIu64" is in seconds", htlc->id);
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "bad locktime");
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) <=
	    get_block_height(lnchn->dstate->topology) + lnchn->dstate->config.min_htlc_expiry) {
		log_unusual(lnchn->log, "HTLC %"PRIu64" expires too soon:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "expiry too soon");
		return;
	}

	if (abs_locktime_to_blocks(&htlc->expiry) >
	    get_block_height(lnchn->dstate->topology) + lnchn->dstate->config.max_htlc_expiry) {
		log_unusual(lnchn->log, "HTLC %"PRIu64" expires too far:"
			    " block %u",
			    htlc->id, abs_locktime_to_blocks(&htlc->expiry));
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "expiry too far");
		return;
	}

	packet = parse_onionpacket(lnchn,
				   htlc->routing, tal_count(htlc->routing));
	if (packet) {
		u8 shared_secret[32];

		if (onion_shared_secret(shared_secret, packet,
					lnchn->dstate->privkey))
			step = process_onionpacket(packet, packet,
						   shared_secret,
						   htlc->rhash.u.u8,
						   sizeof(htlc->rhash));
	}

	if (!step) {
		log_unusual(lnchn->log, "Bad onion, failing HTLC %"PRIu64,
			    htlc->id);
		command_htlc_set_fail(lnchn, htlc, BAD_REQUEST_400,
				      "invalid onion");
		goto free_packet;
	}

	switch (step->nextcase) {
	case ONION_END:
		if (only_dest)
			goto free_packet;
		invoice = find_unpaid(lnchn->dstate->invoices, &htlc->rhash);
		if (!invoice) {
			log_unusual(lnchn->log, "No invoice for HTLC %"PRIu64,
				    htlc->id);
			log_add_struct(lnchn->log, " rhash=%s",
				       struct sha256, &htlc->rhash);
			if (unlikely(!lnchn->dstate->dev_never_routefail))
				command_htlc_set_fail(lnchn, htlc,
						      UNAUTHORIZED_401,
						      "unknown rhash");
			goto free_packet;
		}

		if (htlc->msatoshi != invoice->msatoshi) {
			log_unusual(lnchn->log, "Short payment for '%s' HTLC %"PRIu64
				    ": %"PRIu64" not %"PRIu64 " satoshi!",
				    invoice->label,
				    htlc->id,
				    htlc->msatoshi,
				    invoice->msatoshi);
			command_htlc_set_fail(lnchn, htlc,
					      UNAUTHORIZED_401,
					      "incorrect amount");
			goto free_packet;
		}

		log_info(lnchn->log, "Immediately resolving '%s' HTLC %"PRIu64,
			 invoice->label, htlc->id);

		resolve_invoice(lnchn->dstate, invoice);
		set_htlc_rval(lnchn, htlc, &invoice->r);
		command_htlc_fulfill(lnchn, htlc);
		goto free_packet;

	case ONION_FORWARD:
		route_htlc_onwards(lnchn, htlc, step->hoppayload->amt_to_forward, step->next->nexthop,
				   serialize_onionpacket(step, step->next), only_dest);
		goto free_packet;
	default:
		log_info(lnchn->log, "Unknown step type %u", step->nextcase);
		command_htlc_set_fail(lnchn, htlc, VERSION_NOT_SUPPORTED_505,
				      "unknown step type");
		goto free_packet;
	}

free_packet:
	tal_free(packet);
}

static void our_htlc_failed(struct LNchannel *lnchn, struct htlc *htlc)
{
	assert(htlc_owner(htlc) == LOCAL);
	if (htlc->src) {
		set_htlc_fail(htlc->src->lnchn, htlc->src,
			      htlc->fail, tal_count(htlc->fail));
		command_htlc_fail(htlc->src->lnchn, htlc->src);
	} else
		complete_pay_command(lnchn->dstate, htlc);
}

static void our_htlc_fulfilled(struct LNchannel *lnchn, struct htlc *htlc)
{
	if (htlc->src) {
		set_htlc_rval(htlc->src->lnchn, htlc->src, htlc->r);
		command_htlc_fulfill(htlc->src->lnchn, htlc->src);
	} else {
		complete_pay_command(lnchn->dstate, htlc);
	}
}

/* FIXME: Slow! */
static struct htlc *htlc_with_source(struct LNchannel *lnchn, struct htlc *src)
{
	struct htlc_map_iter it;
	struct htlc *h;

	for (h = htlc_map_first(&lnchn->htlcs, &it);
	     h;
	     h = htlc_map_next(&lnchn->htlcs, &it)) {
		if (h->src == src)
			return h;
	}
	return NULL;
}

