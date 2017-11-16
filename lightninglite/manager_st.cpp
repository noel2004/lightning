
#include <cassert>
#include "manager_st.h"

extern "C" {
#include "c/manager.h"
}

using namespace lnl_st;

namespace {

    inline const struct htlc* chain_source(const htlcChain& c) { return c.first.first; }
    inline const struct LNchannel* chain_source_chn(const htlcChain& c) { return c.first.second; }
    inline const struct htlc* chain_downstream(const htlcChain& c) { return c.second.first; }
    inline const struct LNchannel* chain_downstream_chn(const htlcChain& c) { return c.second.second; }
    inline bool  we_has(void* p) { return p; }

    static const htlcChain nullhtlcChain = { {nullptr, nullptr}, {nullptr, nullptr} };
}
 

extern "C" {

    struct LNchannelQuery
    {
        const struct LNchannel *p;
    };

    struct LNchannelComm
    {
        struct LNchannel *p;
        LNchannels_impl  *mgr;
    };

    void    lite_update_channel(struct LNchannels *mgr_, const struct LNchannel *lnchn)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);

        auto& ipk = pubkey_from_raw(lnchn_channel_pubkey(lnchn));
        auto fret = mgr->channel_map.find(ipk);
        if (fret == mgr->channel_map.end()) {
            mgr->channel_map.insert(LNchannels_impl::channelmap_type::value_type(
                ipk, lnchn_channel_copy(lnchn, LNchn_copy_all, nullptr)));
        }
        else {
            lnchn_channel_update(fret->second, lnchn, LNchn_copy_all);
        }

    }

    void    lite_reg_htlc(struct LNchannels *mgr_, const struct LNchannel *lnchn, 
        const struct sha256* hash, const struct htlc *htlc)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);
        auto ret = mgr->htlc_map.insert(LNchannels_impl::htlcmap_type::value_type(
            shakey_from_raw(hash), nullhtlcChain));
        if (ret.second) {
            (lnchn_htlc_route_is_upstream(htlc) ?
                (htlcItem&)(ret.first->second.first) : (ret.first->second.second))
                = { htlc, lnchn };
        }
        else {
            auto& hi = lnchn_htlc_route_is_upstream(htlc) ?
                (htlcItem&)(ret.first->second.first) : (ret.first->second.second);
            assert(hi.first == nullptr);
            hi = { htlc, lnchn };
        }
    }

    void    lite_unreg_htlc(struct LNchannels *mgr_, const struct sha256* hash, 
        const struct htlc *htlc)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);
        auto ret = mgr->htlc_map.find(shakey_from_raw(hash));
        assert(ret != mgr->htlc_map.end());

        auto& hi = lnchn_htlc_route_is_upstream(htlc) ?
            (htlcItem&)(ret->second.first) : (ret->second.second);

        assert(hi.first == htlc);
        hi.first = nullptr;

        if (chain_source(ret->second) == nullptr
            && chain_downstream(ret->second) == nullptr)
            mgr->htlc_map.erase(ret);
    }

    struct LNchannelQuery* lite_query_channel(struct LNchannels *mgr_, const struct pubkey *id)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);
        auto fret = mgr->channel_map.find(pubkey_from_raw(id));
        if (fret == mgr->channel_map.end())return nullptr;
        return new LNchannelQuery{ fret->second };
    }

    struct LNchannelQuery* lite_query_channel_from_htlc(struct LNchannels *mgr_, 
        const struct sha256 *hash, int issrc)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);
        auto ret = mgr->htlc_map.find(shakey_from_raw(hash));
        assert(ret != mgr->htlc_map.end());

        return new LNchannelQuery{ 
            issrc ? chain_source_chn(ret->second) : chain_downstream_chn(ret->second) };
    }

    void    lite_release_chn(struct LNchannels * /*mgr_*/, const struct LNchannelQuery* chn)
    {
        delete chn;
    }

    struct LNchannelComm*  lite_comm_channel(struct LNchannels *mgr_, struct LNchannelQuery *q)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);
        auto r = new LNchannelComm{ nullptr, mgr };
        auto fret = mgr->channel_map.find(pubkey_from_raw(lnchn_channel_pubkey(q->p)));
        assert(fret != mgr->channel_map.end());
        r->p = fret->second;
        return r;
    }

    struct LNchannelComm* lite_comm_channel_from_htlc(struct LNchannels *mgr, 
        const struct sha256* hash, int issrc)
    {
        auto q = lite_query_channel_from_htlc(mgr, hash, issrc);
        auto r = lite_comm_channel(mgr, q);
        lite_release_chn(mgr, q);
        return r;
    }

    void lite_release_comm(struct LNchannels * /*mgr_*/, struct LNchannelComm *c)
    {
        delete c;
    }

    const struct htlc *lite_query_htlc_direct(struct LNchannels *mgr_, 
        const struct sha256* hash, int issrc)
    {
        auto mgr = static_cast<LNchannels_impl*>(mgr_);
        auto ret = mgr->htlc_map.find(shakey_from_raw(hash));
        assert(ret != mgr->htlc_map.end());

        return issrc ? chain_source(ret->second) : chain_downstream(ret->second);
    }

    void    lite_release_htlc(struct LNchannels * /*mgr_*/, const struct htlc * /*htlc*/)
    {
        //do nothing: we just keep the original htlc
    }

    void    lite_query_commit_txid(const struct LNchannelQuery *q, const struct sha256_double *commit_txid[3])
    {
        lnchn_channel_commits(q->p, commit_txid);
    }

    const struct pubkey *lite_query_pubkey(const struct LNchannelQuery *q)
    {
        return lnchn_channel_pubkey(q->p);
    }


    int lite_query_isactive(const struct LNchannelQuery *q)
    {
        auto s = lnchn_channel_state(q->p);
        return s < STATE_SHUTDOWN && s >= STATE_NORMAL;
    }

    const struct sha256_double *lite_query_anchor_txid(const struct LNchannelQuery *q)
    {
        return nullptr;
    }

    const struct htlc *lite_query_htlc(const struct LNchannelQuery *q, const struct sha256* hash)
    {
        //CAUTION: don't do this in a real implement, the return htlc should be a copy of original one
        return lnchn_channel_htlc(q->p, hash);
    }


    void lite_notify_chn_commit(struct LNchannelComm* c)
    {
        c->mgr->updated_list.insert(pubkey_from_raw(lnchn_channel_pubkey(c->p)));
    }

    void lite_notify_chn_htlc_update(struct LNchannelComm* c, const struct sha256* hash)
    {
        //CAUTION: don't do this in a real implement
        lnchn_update_htlc(c->p, hash);
    }


}

