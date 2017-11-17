#include "message_demo.h"

using namespace lnl_demo;

extern "C" {
#include "c/message.h"

    void    lite_msg_open(struct LNmessage *msg_, const struct pubkey *target,
        const struct LNchannel_config *nego_config,
        const struct sha256 *revocation_hash,
        const struct pubkey *channel_key[2])
    {
        auto msg = static_cast<LNmessage_impl*>(msg_);

    }

    void    lite_msg_anchor(struct LNmessage *msg_, const struct pubkey *target,
        const struct sha256_double *txid,
        unsigned int index,
        unsigned long long amount,
        const struct sha256 *revocation_hash)
    {
        auto msg = static_cast<LNmessage_impl*>(msg_);

    }

    void    lite_msg_first_commit(struct LNmessage *msg_,
        const struct pubkey *target,
        const struct sha256 *revocation_hash,
        const struct ecdsa_signature_ *sig
    )
    {
        auto msg = static_cast<LNmessage_impl*>(msg_);

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
        auto msg = static_cast<LNmessage_impl*>(msg_);
    }

    void    lite_msg_commit_resp(struct LNmessage *msg_,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *revocation_hash,
        const struct sha256 *revocation_image
    )
    {
        auto msg = static_cast<LNmessage_impl*>(msg_);

    }

    void    lite_msg_commit_resp_ack(struct LNmessage *msg_,
        const struct pubkey *target,
        unsigned long long commit_num,
        const struct sha256 *revocation_image
    )
    {
        auto msg = static_cast<LNmessage_impl*>(msg_);

    }

    void    lite_msg_commit_final(struct LNmessage *msg_, 
        const struct pubkey *target)
    {
        auto msg = static_cast<LNmessage_impl*>(msg_);
    }

}



