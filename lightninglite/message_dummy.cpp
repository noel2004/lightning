
#include "dummy.h"




extern "C" {
#include "lightningcore/state.h"
#include "c/message.h"

    void    lite_msg_open(struct LNmessage *msg, const struct pubkey *target,
        const struct LNchannel_config *nego_config,
        const struct sha256 *revocation_hash,
        const struct pubkey *channel_key[2])
    {

    }

    void    lite_msg_anchor(struct LNmessage *msg, const struct pubkey *target,
        const struct sha256_double *txid,
        unsigned int index,
        unsigned long long amount,
        const struct sha256 *revocation_hash)
    {

    }

    void    lite_msg_first_commit(struct LNmessage *msg,
        const struct pubkey *target,
        const struct sha256 *revocation_hash,
        const struct ecdsa_signature_ *sig
    )
    {

    }

    void    lite_msg_commit_purpose(struct LNmessage *msg,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *next_revocation,
        unsigned int num_htlc_entry,
        const struct msg_htlc_entry *htlc_entry
    )
    {

    }

    void    lite_msg_commit_resp(struct LNmessage *msg,
        unsigned long long commit_num,
        const struct ecdsa_signature_ *sig,
        const struct sha256 *revocation_hash,
        const struct sha256 *revocation_image
    )
    {

    }

    void    lite_msg_commit_resp_ack(struct LNmessage *msg,
        unsigned long long commit_num,
        const struct sha256 *revocation_image
    )
    {

    }

    void    lite_msg_commit_final(struct LNmessage *msg)
    {

    }

}

namespace lnl_dummy {

    void init_messages(struct lightningd_state* state) {

    }

    void clean_messages(struct lightningd_state* state) {

    }
}


