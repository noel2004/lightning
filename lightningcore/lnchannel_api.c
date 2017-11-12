#include "include/lnchannel_api.h"
#include "lnchannel_internal.h"
#include "log.h"
#include "db.h"
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

struct LNcore
{
    struct lightningd_state *dstate;
};


LNCHANNEL_API struct LNcore* LNAPI_init()
{
    struct lightningd_state *dstate = tal(NULL, struct lightningd_state);

    dstate->log_book = new_log_book(dstate, 20 * 1024 * 1024, LOG_INFORM);
    dstate->base_log = new_log(dstate, dstate->log_book,
        "lightningd(%u):", (int)getpid());

    db_init(dstate);
    lite_init_channels(dstate);
    lite_init_messagemgr(dstate);
    lite_init_paymentmgr(dstate);
    btcnetwork_init(dstate);

    log_info(dstate->base_log, "Hello world!");

    dstate->testnet = true;
    dstate->default_redeem_address = NULL;
 
    return dstate;

}

LNCHANNEL_API void LNAPI_uninit(struct LNcore* pcore)
{
    tal_free(pcore->dstate);
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
