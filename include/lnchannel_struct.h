
#ifndef LIGHTNING_CORE_LNCHANNEL_STRUCTS_H
#define LIGHTNING_CORE_LNCHANNEL_STRUCTS_H

#ifdef __cplusplus
extern "C" {
#endif

    struct LNchannel;
    struct LNchannels;
    struct htlc;
    struct pubkey;
    struct sha256;
    struct sha256_double;
    struct ecdsa_signature_;
    struct LNchannel_config;
    struct msg_htlc_entry;

    struct LNchannel_config
    {
        unsigned long         delay;
        unsigned long         min_depth;
        unsigned long long    initial_fee_rate;
        unsigned long long    purpose_satoshi;
    };

    struct msg_htlc_add
    {
        unsigned int       expiry;
        unsigned long long mstatoshi;
    };

    struct msg_htlc_del
    {
        const struct preimage *r; /* NULL if being revoked*/
        const unsigned char* fail;
        unsigned int failflag; /* 1: indicate htlc fail from end so retry is not needed*/
    };

    struct msg_htlc_entry
    {
        const struct sha256 *rhash;
        int   action_type; /*1 is add and 0 is del*/
        union {
            struct msg_htlc_add add;
            struct msg_htlc_del del;
        } action;
    };

    enum outsourcing_deliver {
        OUTSOURCING_DELIVER_DONE,
        OUTSOURCING_DELIVER_FAILED,
        OUTSOURCING_DELIVER_CONFIRMED,
    };


#ifdef __cplusplus
}
#endif

#endif