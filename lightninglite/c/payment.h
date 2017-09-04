#ifndef LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H
#define LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H

struct Payments;
struct LNchannel;
struct htlc;
struct pubkey;
struct sha256;

/*return 1 for exist invoice or 0 for not*/
int     lite_check_invoice(struct Payments *payment, const struct sha256* rhash);

void    lite_resolve_invoice(struct Payments *payment, const struct LNchannel *lnchn, 
    const struct htlc* invoice_htlc);


#endif