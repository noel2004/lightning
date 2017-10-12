#ifndef LIGHTNING_CORE_LNCHANNEL_API_H
#define LIGHTNING_CORE_LNCHANNEL_API_H

struct LNchannel;
struct htlc;
struct pubkey;
struct sha256;

const struct pubkey* LNAPI_channel_pubkey(const struct LNchannel*);
const struct htlc* LNAPI_channel_htlc(const struct LNchannel*, const struct sha256*);

typedef enum LNchannelPart_e
{
    LNchn_copy_trivial = 0,
    LNchn_copy_anchor = 1,
    LNchn_copy_ourcommit = 2,
    LNchn_copy_theircommit = 4,
    LNchn_copy_closing = 8,
    LNchn_copy_htlcs = 16, /*not implemeted yet*/
    LNchn_copy_all = LNchn_copy_closing * 2 - 1,
} LNchannelPart;

struct LNchannel* LNAPI_channel_copy(const struct LNchannel*, unsigned int copy_mask, void *tal_ctx);
void   NAPI_channel_copy(struct LNchannel*, const struct LNchannel*, unsigned int copy_mask);

struct htlc* LNAPI_htlc_copy(const struct htlc*, void *tal_ctx);

void         LNAPI_object_release(void *);

#endif

