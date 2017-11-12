
#include "dummy.h"
#include <memory>
#include <array>

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

}

extern "C" {
#include "c/message.h"

    struct LNmessage {
        void* alloc_ctx;
        struct lightningd_state* state;
    };

    void    lite_init_messagemgr(struct lightningd_state* state) {
        state->message_svr = new LNmessage;
        state->message_svr->alloc_ctx = state;
        state->message_svr->state = state;
    }

    void    lite_clean_messagemgr(struct lightningd_state* state) {
        delete state->message_svr;
        state->message_svr = nullptr;
    }

#define WRAP_SHRPTR(TYPE, SUFFIX, NAME) pointer_wrapper<TYPE>{\
    std::shared_ptr<TYPE>(simple_##SUFFIX##_create(msg->alloc_ctx, \
    simple_##SUFFIX##_data(NAME)), simple_freeobjects)}

    void    lite_msg_open(struct LNmessage *msg, const struct pubkey *target,
        const struct LNchannel_config *nego_config,
        const struct sha256 *revocation_hash,
        const struct pubkey *channel_key[2])
    {
        /* TODO: create channel */
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);

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

    void    lite_msg_anchor(struct LNmessage *msg, const struct pubkey *target,
        const struct sha256_double *txid,
        unsigned int index,
        unsigned long long amount,
        const struct sha256 *revocation_hash)
    {
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_anchor,
            p,
            WRAP_SHRPTR(struct sha256_double, sha256double, txid),
            index, amount,
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash)
        ));
    }

    void    lite_msg_first_commit(struct LNmessage *msg,
        const struct pubkey *target,
        const struct sha256 *revocation_hash,
        const struct ecdsa_signature_ *sig
    )
    {
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_first_commit,
            p,
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash),
            WRAP_SHRPTR(struct ecdsa_signature_, ecdsasig, sig)
        ));
    }

    void    lite_msg_commit_purpose(struct LNmessage *msg,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *next_revocation,
        unsigned int num_htlc_entry,
        const struct msg_htlc_entry *htlc_entry
    )
    {
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);

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

    void    lite_msg_commit_resp(struct LNmessage *msg,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *revocation_hash,
        const struct sha256 *revocation_image
    )
    {
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_remote_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct ecdsa_signature_, ecdsasig, sig),
            WRAP_SHRPTR(struct sha256, sha256, revocation_hash),
            WRAP_SHRPTR(struct sha256, sha256, revocation_image)
        ));
    }

    void    lite_msg_commit_resp_ack(struct LNmessage *msg,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct sha256 *revocation_image
    )
    {
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_revo_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct sha256, sha256, revocation_image)
        ));
    }

    void    lite_msg_commit_final(struct LNmessage *msg, 
        const struct pubkey *target)
    {
        auto p = lnl_dummy::dummy_get_channel(msg->state->channels, target);
        lnl_dummy::add_task(std::bind(&lnchn_notify_commit_done,
            p
        ));
    }

}

namespace lnl_dummy {

    void init_messages(struct lightningd_state* state) {
        state->message_svr = new LNmessage{ nullptr, state };
    }

    void clean_messages(struct lightningd_state* state) {
        delete state->message_svr;
    }
}


