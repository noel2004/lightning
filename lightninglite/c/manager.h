#ifndef LIGHTNING_LITE_C_INTERFACE_MANAGER_H
#define LIGHTNING_LITE_C_INTERFACE_MANAGER_H

struct LNchannels;
struct LNchannel;
struct htlc;
struct pubkey;

void    lite_reg_channel(struct LNchannels *mgr, const struct LNchannel *lnchn);
void    lite_reg_htlc(struct LNchannels *mgr, const struct LNchannel *lnchn, const struct htlc *htlc);

struct LNchannel* lite_query_channel(struct LNchannels *mgr, struct pubkey *id);
/* the fast entry to query channel including the sourcing htlc, need to call release */
struct LNchannel* lite_query_htlc_src(struct LNchannels *mgr, const struct sha256* hash);
void    lite_release_query_chn(struct LNchannels *mgr, const struct LNchannel* chn);


#endif
