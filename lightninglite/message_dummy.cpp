
#include "dummy.h"
#include <memory>
#include <array>

using namespace lnl_dummy;

namespace {
    template<class T>
    struct pointer_wrapper
    {
        std::shared_ptr<T> wrapped_p;
        operator const T*() const { return wrapped_p.get(); }
    };

    bool lnchn_notify_open_remote_adapter(struct LNchannel *lnchn,
        const struct pubkey *chnid,                
        const struct LNchannel_config *nego_config,
        const struct sha256 *revocation_hash,     
        const struct pubkey *remote_key1, 
        const struct pubkey *remote_key2
    ) {
        const struct pubkey *k[2] = { remote_key1 , remote_key2 };

        return lnchn_notify_open_remote(lnchn, chnid, nego_config, revocation_hash, k);
    }

    struct LNchannel* dummy_get_channel(LNdummy_impl* core, const struct pubkey *k)
    {
        auto ret = core->channel_map.find(pubkey_from_raw(k));

        return ret == core->channel_map.end() ? nullptr : ret->second;
    }
}



extern "C" {
#include "c/message.h"

#define WRAP_SHRPTR(TYPE, SUFFIX, NAME) pointer_wrapper<TYPE>{\
    std::shared_ptr<TYPE>(simple_##SUFFIX##_create(msg->alloc_ctx, \
    simple_##SUFFIX##_data(NAME)), simple_freeobjects)}

    void    lite_msg_open(struct LNmessage *msg_, const struct pubkey *target,
        const struct LNchannel_config *nego_config,
        const struct sha256 *revocation_hash,
        const struct pubkey *channel_key[2])
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        /* TODO: create channel */
        auto p = dummy_get_channel(msg, target);

        pointer_wrapper<struct LNchannel_config> pconfwrap{ 
            std::shared_ptr<struct LNchannel_config>(new struct LNchannel_config) };        
        *pconfwrap.wrapped_p = *nego_config;

        lnl_dummy::add_task(std::bind(&lnchn_notify_open_remote_adapter,
            p,
            WRAP_SHRPTR(struct pubkey, pubkey, target),
            pconfwrap,
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash),
            WRAP_SHRPTR(struct pubkey, pubkey, channel_key[0]),
            WRAP_SHRPTR(struct pubkey, pubkey, channel_key[1])
        ));
    }

    void    lite_msg_anchor(struct LNmessage *msg_, const struct pubkey *target,
        const struct sha256_double *txid,
        unsigned int index,
        unsigned long long amount,
        const struct sha256 *revocation_hash)
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        auto p = dummy_get_channel(msg, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_anchor,
            p,
            WRAP_SHRPTR(struct sha256_double, sha256double, txid),
            index, amount,
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash)
        ));
    }

    void    lite_msg_first_commit(struct LNmessage *msg_,
        const struct pubkey *target,
        const struct sha256 *revocation_hash,
        const struct ecdsa_signature_ *sig
    )
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        auto p = dummy_get_channel(msg, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_first_commit,
            p,
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash),
            WRAP_SHRPTR(struct ecdsa_signature_, ecdsasig, sig)
        ));
    }

    void    lite_msg_commit_purpose(struct LNmessage *msg_,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *next_revocation,
        unsigned int num_htlc_entry,
        const struct msg_htlc_entry *htlc_entry
    )
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        auto p = dummy_get_channel(msg, target);

        pointer_wrapper<struct msg_htlc_entry> phtlcswrap{
            std::shared_ptr<struct msg_htlc_entry>(
                lnchn_htlc_entry_create(htlc_entry, num_htlc_entry, msg->alloc_ctx),
                lnchn_object_release) 
        };

        lnl_dummy::add_task(std::bind(&lnchn_notify_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct ecdsa_signature_, ecdsasig, sig),
            WRAP_SHRPTR(struct sha256, sha256, next_revocation),
            num_htlc_entry,
            phtlcswrap
        ));
    }

    void    lite_msg_commit_resp(struct LNmessage *msg_,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *revocation_hash,
        const struct sha256 *revocation_image
    )
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        auto p = dummy_get_channel(msg, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_remote_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct ecdsa_signature_, ecdsasig, sig),
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash),
            WRAP_SHRPTR(struct sha256, sha256, revocation_image)
        ));
    }

    void    lite_msg_commit_resp_ack(struct LNmessage *msg_,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct sha256 *revocation_image
    )
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        auto p = dummy_get_channel(msg, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_revo_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct sha256, sha256, revocation_image)
        ));
    }

    void    lite_msg_commit_final(struct LNmessage *msg_, 
        const struct pubkey *target)
    {
        auto msg = static_cast<LNdummy_impl*>(msg_);
        auto p = dummy_get_channel(msg, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_commit_done,
            p
        ));
    }

}



