
#include "dummy.h"
#include <memory>

namespace {
    template<class T>
    struct pointer_wrapper
    {
        std::shared_ptr<T> wrapped_p;
        operator T*() const { return wrapped_p.get(); }
    };
}

extern "C" {
#include "lightningcore/state.h"
#include "c/message.h"

    struct LNmessage {
        void* alloc_ctx;
    };

#define WRAP_SHRPTR(TYPE, SUFFIX, NAME) pointer_wrapper<TYPE>{\
    std::shared_ptr<TYPE>(simple_##SUFFIX##_create(msg->alloc_ctx, \
    simple_##SUFFIX##_data(NAME)), simple_freeobjects)}

    void    lite_msg_open(struct LNmessage *msg, const struct pubkey *target,
        const struct LNchannel_config *nego_config,
        const struct sha256 *revocation_hash,
        const struct pubkey *channel_key[2])
    {
        std::shared_ptr<struct pubkey> ptarget(simple_pubkey_create(msg->alloc_ctx, simple_pubkey_data(target)), simple_freeobjects);
    }

    void    lite_msg_anchor(struct LNmessage *msg, const struct pubkey *target,
        const struct sha256_double *txid,
        unsigned int index,
        unsigned long long amount,
        const struct sha256 *revocation_hash)
    {
        auto p = lnl_dummy::dummy_get_channel(target);
        lnl_dummy::add_task(std::bind(&LNAPI_channelnotify_anchor,
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
        auto p = lnl_dummy::dummy_get_channel(target);
        lnl_dummy::add_task(std::bind(&LNAPI_channelnotify_first_commit,
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
        auto p = lnl_dummy::dummy_get_channel(target);
        auto htlcs = LNAPI_htlc_entry_create(num_htlc_entry, msg->alloc_ctx);
        for (size_t i = 0; i < num_htlc_entry; ++i) {
            LNAPI_htlc_entry_fill_hash(htlcs, i, simple_sha256_data(htlc_entry[i].rhash));
            if (htlc_entry[i].action_type == 1 /*add*/) {
                htlcs[i].action.add = htlc_entry[i].action.add;
            }
            else {
                LNAPI_htlc_entry_fill_del(htlcs, i,
                    htlc_entry[i].action.del.r ?
                    simple_preimage_data(htlc_entry[i].action.del.r)
                    : htlc_entry[i].action.del.fail,
                    htlc_entry[i].action.del.r ? 0 :
                    LNAPI_u8arr_size(htlc_entry[i].action.del.fail)
                );
                htlcs[i].action.del.failflag = htlc_entry[i].action.del.failflag;
            }
        }
        lnl_dummy::add_task(std::bind(&LNAPI_channelnotify_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct ecdsa_signature_, ecdsasig, sig),
            WRAP_SHRPTR(struct sha256, sha256, next_revocation),
            num_htlc_entry,
            htlcs
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
        auto p = lnl_dummy::dummy_get_channel(target);
        lnl_dummy::add_task(std::bind(&LNAPI_channelnotify_remote_commit,
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
        auto p = lnl_dummy::dummy_get_channel(target);
        lnl_dummy::add_task(std::bind(&LNAPI_channelnotify_revo_commit,
            p,
            commit_num,
            WRAP_SHRPTR(struct sha256, sha256, revocation_image)
        ));
    }

    void    lite_msg_commit_final(struct LNmessage *msg, 
        const struct pubkey *target)
    {
        auto p = lnl_dummy::dummy_get_channel(target);
        lnl_dummy::add_task(std::bind(&LNAPI_channelnotify_commit_done,
            p
        ));
    }

}

namespace lnl_dummy {

    void init_messages(struct lightningd_state* state) {

    }

    void clean_messages(struct lightningd_state* state) {

    }
}


