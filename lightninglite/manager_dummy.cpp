
#include <unordered_map>
#include <unordered_set>
#include <array>
#include <cassert>
#include "dummy.h"

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
#include "c/manager.h"
}

namespace {
    typedef std::array<unsigned char, SIMPLE_PUBKEY_DATASIZE> iPubkey;
    typedef std::array<unsigned char, SIMPLE_SHA256_DATASIZE> iShakey;

    typedef std::pair<const struct htlc*, const struct LNchannel*> htlcItem;
    typedef std::pair<htlcItem, htlcItem>                           htlcChain;

    inline const struct htlc* chain_source(const htlcChain& c) { return c.first.first; }
    inline const struct LNchannel* chain_source_chn(const htlcChain& c) { return c.first.second; }
    inline const struct htlc* chain_downstream(const htlcChain& c) { return c.second.first; }
    inline const struct LNchannel* chain_downstream_chn(const htlcChain& c) { return c.second.second; }
    inline bool   we_has(void* p) { return p; }

    inline const iShakey shakey_from_raw(const struct sha256* s)
    {
        iShakey k{};
        std::copy(simple_sha256_data(s),
            simple_sha256_data(s) + SIMPLE_SHA256_DATASIZE,
            k.begin());
        return k;
    }

    inline const iPubkey pubkey_from_raw(const struct pubkey* s)
    {
        iPubkey k{};
        std::copy(simple_pubkey_data(s),
            simple_pubkey_data(s) + SIMPLE_PUBKEY_DATASIZE,
            k.begin());
        return k;
    }

    static const htlcChain nullhtlcChain = { {nullptr, nullptr}, {nullptr, nullptr} };
}
 

extern "C" {
    struct LNchannels
    {
        typedef std::unordered_map<iPubkey, struct LNchannel*, iLongKeyHash> channelmap_type;
        channelmap_type channel_map;
        typedef std::unordered_map<iShakey, htlcChain, iLongKeyHash>          htlcmap_type;
        htlcmap_type    htlc_map;

        std::unordered_set<iPubkey, iLongKeyHash>       updated_list;
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
        const struct LNchannel *p;
    };

    struct LNchannelComm
    {
        struct LNchannel *p;
        struct LNchannels *mgr;
    };

    void    lite_update_channel(struct LNchannels *mgr, const struct LNchannel *lnchn)
    {
        auto& ipk = pubkey_from_raw(lnchn_channel_pubkey(lnchn));
        auto fret = mgr->channel_map.find(ipk);
        if (fret == mgr->channel_map.end()) {
            mgr->channel_map.insert(LNchannels::channelmap_type::value_type(
                ipk, lnchn_channel_copy(lnchn, LNchn_copy_all, nullptr)));
        }
        else {
            lnchn_channel_update(fret->second, lnchn, LNchn_copy_all);
        }

    }

    void    lite_reg_htlc(struct LNchannels *mgr, const struct LNchannel *lnchn, 
        const struct sha256* hash, const struct htlc *htlc)
    {
        auto ret = mgr->htlc_map.insert(LNchannels::htlcmap_type::value_type(
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

    void    lite_unreg_htlc(struct LNchannels *mgr, const struct sha256* hash, 
        const struct htlc *htlc)
    {
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

    struct LNchannelQuery* lite_query_channel(struct LNchannels *mgr, const struct pubkey *id)
    {
        auto fret = mgr->channel_map.find(pubkey_from_raw(id));
        if (fret == mgr->channel_map.end())return nullptr;
        return new LNchannelQuery{ fret->second };
    }

    struct LNchannelQuery* lite_query_channel_from_htlc(struct LNchannels *mgr, 
        const struct sha256 *hash, int issrc)
    {
        auto ret = mgr->htlc_map.find(shakey_from_raw(hash));
        assert(ret != mgr->htlc_map.end());

        return new LNchannelQuery{ 
            issrc ? chain_source_chn(ret->second) : chain_downstream_chn(ret->second) };
    }

    void    lite_release_chn(struct LNchannels * /*mgr*/, const struct LNchannelQuery* chn)
    {
        delete chn;
    }

    struct LNchannelComm*  lite_comm_channel(struct LNchannels *mgr, struct LNchannelQuery *q)
    {
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

    void lite_release_comm(struct LNchannels * /*mgr*/, struct LNchannelComm *c)
    {
        delete c;
    }

    const struct htlc *lite_query_htlc_direct(struct LNchannels *mgr, 
        const struct sha256* hash, int issrc)
    {
        auto ret = mgr->htlc_map.find(shakey_from_raw(hash));
        assert(ret != mgr->htlc_map.end());

        return issrc ? chain_source(ret->second) : chain_downstream(ret->second);
    }

    void    lite_release_htlc(struct LNchannels * /*mgr*/, const struct htlc * /*htlc*/)
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

namespace lnl_dummy {
    struct LNchannel* dummy_get_channel(struct LNchannels *, const struct pubkey *) 
    {
        return nullptr; 
    }
}
