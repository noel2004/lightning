#ifndef LIGHTNING_LITE_C_INTERFACE_MESSAGE_H
#define LIGHTNING_LITE_C_INTERFACE_MESSAGE_H

struct LNmessage;
struct LNchannel_config;
struct sha256;
struct sha256_double;
struct pubkey;
struct abs_locktime;
struct preimage;
struct htlc;

/*take target id from channel id*/
void    lite_msg_open(struct LNmessage *msg, const struct pubkey *target, 
    const struct LNchannel_config *nego_config, 
    const struct sha256 *revocation_hash,
    const struct pubkey *channel_key[2]);

void    lite_msg_anchor(struct LNmessage *msg, const struct pubkey *target, 
    const struct sha256_double *txid, 
    unsigned int index, 
    unsigned long long amount);

struct msg_htlc_add
{
    const struct abs_locktime *expiry;
    unsigned long long mstatoshi;
};

struct msg_htlc_del
{
    const struct preimage *r; /* NULL if being revoked*/
    unsigned char* fail;
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

void    lite_msg_commit_purpose(struct LNmessage *msg,
    unsigned int num_htlc_entry,
    const struct msg_htlc_entry *htlc_entry
);

#endif
