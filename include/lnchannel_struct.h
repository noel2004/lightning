
#ifndef LIGHTNING_CORE_LNCHANNEL_STRUCTS_H
#define LIGHTNING_CORE_LNCHANNEL_STRUCTS_H

#ifdef __cplusplus
extern "C" {
#endif

    struct pubkey;
    struct sha256;
    struct sha256_double;
    struct preimage;
    struct ecdsa_signature_;

    struct LNchannel_config
    {
        unsigned long         delay;
        unsigned long         min_depth;
        unsigned long long    initial_fee_rate;
        unsigned long long    purpose_satoshi;
    };


#ifdef __cplusplus
}
#endif

#endif