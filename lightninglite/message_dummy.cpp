
extern "C" {
#include "c/message.h"

    struct LNchannelQuery
    {
        struct LNchannels *p;
    };

    struct LNchannelComm : LNchannelQuery{};

    void    lite_update_channel(struct LNchannels *mgr, const struct LNchannel *lnchn)
    {
    }


    struct LNchannelQuery* lite_query_channel(struct LNchannels *mgr, const struct pubkey *id)
    {
    }

    struct LNchannelQuery* lite_query_channel_from_htlc(struct LNchannels *mgr, const struct sha256* hash, int issrc)
    {

    }

    void    lite_release_chn(struct LNchannels *mgr, const struct LNchannelQuery* chn)
    {

    }

    struct LNchannelComm*  lite_comm_channel(struct LNchannels *mgr, struct LNchannelQuery *q)
    {

    }

    struct LNchannelComm* lite_comm_channel_from_htlc(struct LNchannels *mgr, const struct sha256* hash, int issrc)
    {

    }

    void lite_release_comm(struct LNchannels *mgr, struct LNchannelComm *c)
    {

    }

    const struct htlc *lite_query_htlc_direct(struct LNchannels *mgr, const struct sha256* hash, int issrc)
    {

    }

    void    lite_release_htlc(struct LNchannels *mgr, const struct htlc *htlc)
    {

    }

    void    lite_query_commit_txid(const struct LNchannelQuery *q, struct sha256_double *commit_txid[3])
    {

    }

    const struct pubkey *lite_query_pubkey(const struct LNchannelQuery *q)
    {

    }


    int lite_query_isactive(const struct LNchannelQuery *q)
    {

    }

    const struct sha256_double *lite_query_anchor_txid(const struct LNchannelQuery *q)
    {

    }

    const struct htlc *lite_query_htlc(const struct LNchannelQuery *q, const struct sha256* hash)
    {

    }


    void lite_notify_chn_commit(struct LNchannelComm* c)
    {

    }

    void lite_notify_chn_htlc_update(struct LNchannelComm* c, const struct sha256* hash)
    {

    }

}
