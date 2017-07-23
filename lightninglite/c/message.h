#ifndef LIGHTNING_LITE_C_INTERFACE_MESSAGE_H
#define LIGHTNING_LITE_C_INTERFACE_MESSAGE_H

struct LNmessage;
struct LNchannel_config;
struct sha256;
struct sha256_double;
struct pubkey;

/*take target id from channel id*/
void    lite_msg_open(struct LNmessage *msg, 
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash[2],
    const struct pubkey *channel_key[2]);

void    lite_msg_anchor(struct LNmessage *msg);

#endif
