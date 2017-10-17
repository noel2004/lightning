#include "lnchannel_api.h"
#include "lnchannel.h"
#include "lnchannel_internal.h"
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "bitcoin/tx.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include "bitcoin/preimage.h"

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

int         LNAPI_u8arr_size(const unsigned char* str) { return tal_len(str); }

struct msg_htlc_entry* LNAPI_htlc_entry_create(unsigned int size, void *tal_ctx) 
{ return tal_arrz(tal_ctx, struct msg_htlc_entry, size); }

void        LNAPI_htlc_entry_fill_hash(struct msg_htlc_entry* h, unsigned int index, const unsigned char* hash)
{
    struct sha256* p = talz(h, struct sha256);
    memcpy(p->u.u8, hash, sizeof(p->u.u8));
    h[index].rhash = p;
}

void        LNAPI_htlc_entry_fill_del(struct msg_htlc_entry* h, unsigned int index,
    const unsigned char* data, unsigned int sz/*if sz is zero, fill r instead of fail*/)
{
    if (sz == 0) {
        struct preimage *r = talz(h, struct preimage);
        memcpy(r->r, data, sizeof(r->r));
        h[index].action.del.r = r;
    }
    else {
        h[index].action.del.fail = tal_dup_arr(h, u8, data, sz, 0);
    }
}

void         LNAPI_object_release(const void * p)
{
    tal_free(p);
}

static     int check_failure(struct LNchannel *lnchn)
{
    return 0;
}

int        LNAPI_lnchn_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash)
{
    return lnchn_update_htlc(lnchn, rhash) ? 0 : check_failure(lnchn);
}

int        LNAPI_lnchn_do_commit(struct LNchannel *chn)
{
    return lnchn_do_commit(chn) ? 0 : check_failure(chn);
}

int        LNAPI_channel_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash)
{
    return lnchn_update_htlc(lnchn, rhash) ? 0 : check_failure(lnchn);
}

int        LNAPI_channel_open_anchor(struct LNchannel *lnchn, 
    const unsigned char* txdata, unsigned int txdata_sz)
{
    const u8* cursor = txdata;
    size_t pos = txdata_sz;
    struct bitcoin_tx *tx = pull_bitcoin_tx(lnchn, &cursor, &pos);
    return lnchn_open_anchor(lnchn, tx) ? 0 : check_failure(lnchn);
}

int        LNAPI_channelnotify_open_remote(struct LNchannel *chn,
    const struct pubkey *remotechnid,
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash,
    const struct pubkey *remote_commit_key,
    const struct pubkey *remote_final_key
)
{
    const struct pubkey *pk[2] = { remote_commit_key , remote_final_key };
    return lnchn_notify_open_remote(chn, remotechnid, nego_config, 
        revocation_hash, pk) ? 0 : check_failure(chn);
}

int        LNAPI_channelnotify_anchor(struct LNchannel *chn,
    const struct sha256_double *txid,
    unsigned int index,
    unsigned long long amount,
    const struct sha256 *revocation_hash
)
{
    return lnchn_notify_anchor(chn, txid, index, amount, revocation_hash)
        ? 0 : check_failure(chn);
}

int        LNAPI_channelnotify_first_commit(struct LNchannel *chn,
    const struct sha256 *revocation_hash,
    const struct ecdsa_signature_ *sig
)
{
    return lnchn_notify_first_commit(chn, revocation_hash, sig) ?
        0 : check_failure(chn);
}

int        LNAPI_channelnotify_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    unsigned int num_htlc_entry,
    const struct msg_htlc_entry *htlc_entry
)
{
    return lnchn_notify_commit(chn, commit_num, sig, 
        next_revocation, num_htlc_entry, htlc_entry) ? 0 : check_failure(chn);
}

int        LNAPI_channelnotify_remote_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    const struct sha256 *revocation_image
)
{
    return lnchn_notify_remote_commit(chn, commit_num, sig, 
        next_revocation, revocation_image) ? 0 : check_failure(chn);
}

int        LNAPI_channelnotify_revo_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct sha256 *revocation_image
)
{
    return lnchn_notify_revo_commit(chn, commit_num, revocation_image)
        ? 0 : check_failure(chn);
}

int        LNAPI_channelnotify_commit_done(struct LNchannel *chn)
{
    return lnchn_notify_commit_done(chn)? 0 : check_failure(chn);
}