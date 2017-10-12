
#include <unordered_map>
#include <array>

namespace {

    struct iLongKeyHash
    {
        template<class L>
        size_t operator()(const L& i) const
        {
            static const size_t szsz = sizeof(size_t);
            size_t v;
            memcpy(&v, i.data() + SIMPLE_PUBKEY_DATASIZE - szsz, szsz);
            return v;
        }
    };

}

extern "C" {
#include "bitcoin/simple.h"
#include "lightningcore/state.h"
#include "lightningcore/lnchannel_api.h"
#include "c/manager.h"
}

namespace {
    typedef std::array<unsigned char, SIMPLE_PUBKEY_DATASIZE> iPubkey;
    typedef std::array<unsigned char, SIMPLE_SHA256_DATASIZE> iShakey;

    typedef std::pair<struct htlc*, struct LNchannels*>       htlcItem;
    typedef std::pair<htlcItem, htlcItem>                     htlcChain;

    inline struct htlc* chain_source(const htlcChain& c) { return c.first.first; }
    inline struct LNchannels* chain_source_chn(const htlcChain& c) { return c.first.second; }
    inline struct htlc* chain_downstream(const htlcChain& c) { return c.second.first; }
    inline struct LNchannels* chain_downstream_chn(const htlcChain& c) { return c.second.second; }
    inline bool   we_has(void* p) { return p; }
}
 

extern "C" {
    struct LNchannels
    {
        std::unordered_map<iPubkey, struct LNchannels*, iLongKeyHash> channel_map;
        std::unordered_map<iShakey, htlcChain, iLongKeyHash>       htlc_map;
    };

    void    lite_init_channels(struct lightningd_state* state)
    {
        delete state->channels;
        state->channels = new LNchannels;
    }

    void    lite_clean_channels(struct lightningd_state* state)
    {
        delete state->channels;
    }

    struct LNchannelQuery
    {
        struct LNchannels *p;
    };

    struct LNchannelComm : LNchannelQuery {};

    void    lite_update_channel(struct LNchannels *mgr, const struct LNchannel *lnchn)
    {
    }

    void    lite_reg_htlc(struct LNchannels *mgr, const struct LNchannel *lnchn, const struct htlc *htlc)
    {

    }

    void    lite_unreg_htlc(struct LNchannels *mgr, const struct htlc *htlc)
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

