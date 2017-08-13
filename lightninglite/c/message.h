#ifndef LIGHTNING_LITE_C_INTERFACE_MESSAGE_H
#define LIGHTNING_LITE_C_INTERFACE_MESSAGE_H

struct LNmessage;
struct LNchannel_config;
struct sha256;
struct sha256_double;
struct pubkey;

/*take target id from channel id*/
void    lite_msg_open(struct LNmessage *msg, const struct pubkey *target, 
    const struct LNchannel_config *nego_config, 
    const struct sha256 *revocation_hash,
    const struct pubkey *channel_key[2]);

void    lite_msg_anchor(struct LNmessage *msg, const struct pubkey *target, 
    const struct sha256_double *txid, 
    unsigned int index, 
    unsigned long long amount);

void    lite_msg_anchor_ack(struct LNmessage *msg /*, 2-of-2 txid*/);

#endif
