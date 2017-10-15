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

void  LNAPI_channel_commits(const struct LNchannel* chn, const struct sha256_double* commitids[3])
{
    commitids[0] = chn->local.commit ? &chn->local.commit->txid : NULL;
    commitids[1] = chn->remote.commit ? &chn->remote.commit->txid : NULL;
    commitids[2] = chn->rt.their_last_commit ? &chn->rt.their_last_commit->txid : NULL;
}

int   LNAPI_channel_state(const struct LNchannel* chn)
{
    return chn->state;
}

const struct htlc* LNAPI_channel_htlc(const struct LNchannel* chn, const struct sha256* key)
{
    return htlc_get_any(&chn->htlcs, key);
}

struct LNchannel* LNAPI_channel_copy(const struct LNchannel* chn,
    unsigned int copy_mask, void *tal_ctx)
{
    struct LNchannel *lnchn = talz((tal_t*)tal_ctx, struct LNchannel);
    htlc_map_init(&lnchn->htlcs);
    shachain_init(&lnchn->their_preimages);

    NAPI_channel_update(lnchn, chn, copy_mask);
    return lnchn;
}

void   NAPI_channel_update(struct LNchannel* dst, const struct LNchannel* src, unsigned int copy_mask)
{
#define SIMPLE_CREATE(NAME, TYPE) if(!dst->NAME){dst->NAME  = tal_dup(dst, TYPE, src->NAME);}\
                                    else memcpy(dst->NAME, src->NAME, sizeof(TYPE))
#define SIMPLE_REPLACE(NAME, TYPE) tal_free(dst->NAME),dst->NAME  = tal_dup(dst, TYPE, src->NAME)
#define SIMPLE_REPLACEARR(NAME, TYPE) tal_free(dst->NAME),dst->NAME  = tal_dup_arr(dst, TYPE, src->NAME, (tal_len(src->NAME)), 0)
#define SIMPLE_COPY(NAME) memcpy(&dst->NAME, &src->NAME, sizeof(dst->NAME))

    //trivial
    dst->state = src->state;
    dst->state_height = src->state_height;
    SIMPLE_CREATE(id, struct pubkey);
    if(src->notify_fail_reason)SIMPLE_REPLACEARR(notify_fail_reason, char);
    if(src->rt.temp_errormsg)SIMPLE_REPLACEARR(rt.temp_errormsg, u8);

    if (copy_mask & LNchn_copy_anchor)
    {
        dst->anchor.txid = src->anchor.txid;
        dst->anchor.index = src->anchor.index;
        dst->anchor.satoshis = src->anchor.satoshis;
        dst->anchor.min_depth = src->anchor.min_depth;
        dst->anchor.ok_depth = src->anchor.ok_depth;
        dst->anchor.ours = src->anchor.ours;
        if (src->anchor.input)SIMPLE_REPLACE(anchor.input, struct anchor_input);
        SIMPLE_REPLACEARR(anchor.witnessscript, u8);
        /*TODO: need bitcoin tx copy*/
        dst->anchor.tx = NULL;
    }

    if (copy_mask & LNchn_copy_ourcommit)
    {
        SIMPLE_COPY(local);
        if (src->local.commit) {
            SIMPLE_REPLACE(local.commit, struct commit_info);
            SIMPLE_REPLACE(local.commit->cstate, struct channel_state);
            SIMPLE_REPLACE(local.commit->sig, ecdsa_signature);
            SIMPLE_REPLACE(local.staging_cstate, struct channel_state);
            dst->local.commit->tx = NULL;
        }        
    }

    if (copy_mask & LNchn_copy_theircommit)
    {
        SIMPLE_COPY(remote);
        if (src->remote.commit) {
            SIMPLE_REPLACE(remote.commit, struct commit_info);
            SIMPLE_REPLACE(remote.commit->cstate, struct channel_state);
            SIMPLE_REPLACE(remote.commit->sig, ecdsa_signature);
            SIMPLE_REPLACE(remote.staging_cstate, struct channel_state);
            dst->remote.commit->tx = NULL;
        }

        if (src->rt.their_last_commit) {
            SIMPLE_REPLACE(rt.their_last_commit, struct commit_info);
            SIMPLE_REPLACE(rt.their_last_commit->cstate, struct channel_state);
            SIMPLE_REPLACE(rt.their_last_commit->sig, ecdsa_signature);
            dst->rt.their_last_commit->tx = NULL;
        }        
    }

    if (copy_mask & LNchn_copy_closing)
    {
        SIMPLE_COPY(closing);
        if (src->closing.their_sig) { 
            SIMPLE_REPLACE(closing.their_sig, ecdsa_signature);
            SIMPLE_REPLACEARR(closing.our_script, u8);
            SIMPLE_REPLACEARR(closing.our_script, u8);
        }
    }

}

struct htlc* LNAPI_htlc_copy(const struct htlc* src, void *tal_ctx)
{
    struct htlc *dst = talz((tal_t*)tal_ctx, struct htlc);

    *dst = *src;

    if (src->r) { SIMPLE_CREATE(r, struct preimage); }
    if (src->fail) { SIMPLE_REPLACEARR(fail, u8); }
    if (src->src_expiry) { SIMPLE_REPLACE(src_expiry, struct abs_locktime); }

    return dst;
}

int         LNAPI_htlc_route_is_upstream(const struct htlc *h) { return h->routing & 1; }

void         LNAPI_object_release(void * p)
{
    tal_free(p);
}
