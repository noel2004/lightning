#ifndef LIGHTNING_CORE_LNCHANNEL_API_H
#define LIGHTNING_CORE_LNCHANNEL_API_H

#ifdef __cplusplus
extern "C" {
#endif

struct LNchannel;
struct LNchannels;
struct htlc;
struct pubkey;
struct sha256;
struct sha256_double;
struct ecdsa_signature_;
struct LNchannel_config;
struct msg_htlc_entry;

struct LNchannel_config
{
    unsigned long         delay;
    unsigned long         min_depth;
    unsigned long long    initial_fee_rate;
    unsigned long long    purpose_satoshi;
};

const struct pubkey* LNAPI_channel_pubkey(const struct LNchannel*);
void               LNAPI_channel_commits(const struct LNchannel*, const struct sha256_double*[3]);
const struct htlc* LNAPI_channel_htlc(const struct LNchannel*, const struct sha256*);
int                LNAPI_channel_state(const struct LNchannel*);
const struct sha256_double* LNAPI_channel_anchor_txid(struct LNchannel *lnchn);

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
void   NAPI_channel_update(struct LNchannel*, const struct LNchannel*, unsigned int copy_mask);

struct htlc* LNAPI_htlc_copy(const struct htlc*, void *tal_ctx);
/*take API from htlc.h*/
int         LNAPI_htlc_route_is_upstream(const struct htlc *h);

/*message helpers*/
int         LNAPI_u8arr_size(const unsigned char* str);
struct msg_htlc_entry* LNAPI_htlc_entry_create(unsigned int, void *tal_ctx);
void        LNAPI_htlc_entry_fill_hash(struct msg_htlc_entry*, unsigned int index, const unsigned char*);
void        LNAPI_htlc_entry_fill_del(struct msg_htlc_entry*, unsigned int index,
    const unsigned char*, unsigned int sz/*if sz is zero, fill r instead of fail*/);

void        LNAPI_object_release(const void *);

/*lnchannel.h wrapper*/
int        LNAPI_channel_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash);
int        LNAPI_channel_do_commit(struct LNchannel *chn);
int        LNAPI_channel_open_anchor(struct LNchannel *lnchn, const unsigned char* txdata, 
    unsigned int txdata_sz);

int        LNAPI_channelnotify_open_remote(struct LNchannel *chn,
    const struct pubkey *remotechnid,                
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash,      
    const struct pubkey *remote_commit_key,
    const struct pubkey *remote_final_key
);
int        LNAPI_channelnotify_anchor(struct LNchannel *chn,
    const struct sha256_double *txid,
    unsigned int index,
    unsigned long long amount,
    const struct sha256 *revocation_hash
);
int        LNAPI_channelnotify_first_commit(struct LNchannel *chn,
    const struct sha256 *revocation_hash,
    const struct ecdsa_signature_ *sig
);
int        LNAPI_channelnotify_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    unsigned int num_htlc_entry,
    const struct msg_htlc_entry *htlc_entry
);
int        LNAPI_channelnotify_remote_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    const struct sha256 *revocation_image
);
int        LNAPI_channelnotify_revo_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct sha256 *revocation_image
);
int        LNAPI_channelnotify_commit_done(struct LNchannel *chn);

#ifdef __cplusplus
}
#endif

#endif

