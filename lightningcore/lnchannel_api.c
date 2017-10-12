#include "lnchannel_api.h"
#include "lnchannel.h"
#include "lnchannel_internal.h"
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>

const struct pubkey* LNAPI_channel_pubkey(const struct LNchannel* chn)
{
    return chn->id;
}

const struct htlc* LNAPI_channel_htlc(const struct LNchannel* chn, const struct sha256* key)
{
    return htlc_get_any(&chn->htlcs, key);
}

struct LNchannel* LNAPI_channel_copy(const struct LNchannel* chn,
    unsigned int copy_mask, void *tal_ctx)
{
    struct LNchannel *lnchn = talz((tal_t*)tal_ctx, struct LNchannel);
    NAPI_channel_copy(lnchn, chn, copy_mask);
    return lnchn;
}

void   NAPI_channel_copy(struct LNchannel* dst, const struct LNchannel* src, unsigned int copy_mask)
{
    size_t sz;
#define SIMPLE_CREATE(NAME, TYPE) if(!dst->NAME){dst->NAME  = tal_dup(dst, TYPE, src->NAME);}\
                                    else memcpy(dst->NAME, src->NAME, sizeof(TYPE))
#define SIMPLE_COPY(NAME) memcpy(&dst->NAME, &src->NAME, sizeof(dst->NAME))

    //trivial
    dst->state = src->state;
    dst->state_height = src->state_height;
    SIMPLE_CREATE(id, struct pubkey);

    if (copy_mask & LNchn_copy_anchor)
    {
        dst->anchor.txid = src->anchor.txid;
        dst->anchor.index = src->anchor.index;
        dst->anchor.satoshis = src->anchor.satoshis;
        dst->anchor.min_depth = src->anchor.min_depth;
        dst->anchor.ok_depth = src->anchor.ok_depth;
        dst->anchor.ours = src->anchor.ours;
        if (src->anchor.input)SIMPLE_CREATE(anchor.input, struct anchor_input);
        if (src->anchor.tx)SIMPLE_CREATE(anchor.tx, struct bitcoin_tx);
        tal_free(dst->anchor.witnessscript);
        sz = tal_len(src->anchor.witnessscript);
        dst->anchor.witnessscript = tal_dup_arr(dst, u8, src->anchor.witnessscript, sz, 0);
    }

    if (copy_mask & LNchn_copy_ourcommit)
    {

    }

    if (copy_mask & LNchn_copy_theircommit)
    {

    }

    lnchn->anchor.ok_depth = -1;
    //	lnchn->order_counter = 0;
    lnchn->their_commitsigs = 0;
    lnchn->closing.their_sig = NULL;
    lnchn->closing.our_script = NULL;
    lnchn->closing.their_script = NULL;
    lnchn->closing.shutdown_order = (s64)-1LL;
    lnchn->closing.closing_order = (s64)-1LL;
    lnchn->closing.sigs_in = 0;
    lnchn->onchain.tx = NULL;
    lnchn->onchain.resolved = NULL;
    lnchn->onchain.htlcs = NULL;
    lnchn->commit_timer = NULL;
    lnchn->fake_close = false;
    lnchn->output_enabled = true;
    lnchn->local.offer_anchor = false;
    lnchn->broadcast_index = 0;
    if (!blocks_to_rel_locktime(dstate->config.locktime_blocks,
        &lnchn->local.locktime))
        fatal("Could not convert locktime_blocks");
    lnchn->local.mindepth = dstate->config.anchor_confirms;
    lnchn->local.commit = lnchn->remote.commit = NULL;
    lnchn->local.staging_cstate = lnchn->remote.staging_cstate = NULL;
    lnchn->log = tal_steal(lnchn, log);
    log_debug(lnchn->log, "New lnchn %p", lnchn);
    lnchn->notify_fail_reason = NULL;

    lnchn->remote.offer_anchor = false;

    htlc_map_init(&lnchn->htlcs);
    //	memset(lnchn->feechanges, 0, sizeof(lnchn->feechanges));
    shachain_init(&lnchn->their_preimages);

    /* init runtime */
    lnchn->rt.outsourcing_counter = 0;
    lnchn->rt.outsourcing_lock = false;
    lnchn->rt.prev_call = NULL;
    lnchn->rt.changed_htlc_cache = NULL;
    lnchn->rt.their_last_commit = NULL;
    lnchn->rt.temp_errormsg = NULL;
    memset(lnchn->rt.feechanges, 0, sizeof(lnchn->rt.feechanges));

    //	tal_add_destructor(lnchn, destroy_lnchn);

}

struct htlc* LNAPI_htlc_copy(const struct htlc* h)
{

}

void         LNAPI_object_release(void * p)
{

}
