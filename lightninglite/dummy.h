#pragma once
#ifndef LIGHTNING_LITE_DUMMY_IMPL_H
#define LIGHTNING_LITE_DUMMY_IMPL_H

#include <functional>
#include "lightningcore/lnchannel.h"
#include "bitcoin/simple.h"

namespace lnl_dummy {

    class task_package_base
    {
    protected:
        virtual void execute() = 0;
    public:
        virtual ~task_package_base(){}
        void operator()() { execute(); }
    };

    template<class F>
    class task_package : public task_package_base
    {
        F funcobj;
        void execute() override { funcobj(); }

    public:
        task_package(const F& o) : funcobj(o) { }

    };

    void  add_task_p(task_package_base*);
    template<class F>
    void  add_task(const F& o) { add_task_p(new task_package<F>(o)); }

    void  dump_tasks();
    void  clear_tasks();

    typedef std::array<unsigned char, SIMPLE_PUBKEY_DATASIZE> iPubkey;
    typedef std::array<unsigned char, SIMPLE_SHA256_DATASIZE> iShakey;

    typedef std::pair<const struct htlc*, const struct LNchannel*>  htlcItem;
    typedef std::pair<htlcItem, htlcItem>                           htlcChain;

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

}//namespace lnl_dummy

#include <unordered_map>
#include <unordered_set>
#include <array>

struct LNchannels{};
struct Payments{};
struct LNmessage {};

namespace lnl_dummy {

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

    class LNdummy_impl : public LNchannels, public Payments, public LNmessage
    {
    public:
        void* alloc_ctx;
        struct lightningd_state* state;

        typedef std::unordered_map<iPubkey, struct LNchannel*, iLongKeyHash>  channelmap_type;
        channelmap_type channel_map;
        typedef std::unordered_map<iShakey, htlcChain, iLongKeyHash> htlcmap_type;
        htlcmap_type    htlc_map;

        std::unordered_set<iPubkey, iLongKeyHash>       updated_list;
    };

}

#endif //LIGHTNING_LITE_DUMMY_IMPL_H

