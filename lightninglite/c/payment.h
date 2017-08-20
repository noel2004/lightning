#ifndef LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H
#define LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H

struct Payments;
struct LNchannel;
struct htlc;
struct pubkey;
struct sha256;


void    lite_resolve_invoice(struct Payments *payment, const struct LNchannel *lnchn, 
    const struct htlc* invoice_htlc);


#endif