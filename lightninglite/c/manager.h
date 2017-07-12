#ifndef LIGHTNING_LITE_C_INTERFACE_MANAGER_H
#define LIGHTNING_LITE_C_INTERFACE_MANAGER_H

struct LNchannels;
struct LNchannel;
struct htlc;

void    lite_reg_channel(struct LNchannels *mgr, const struct LNchannel *lnchn);
void    lite_reg_htlc(struct LNchannels *mgr, const struct LNchannel *lnchn, const struct htlc *htlc);

#endif
