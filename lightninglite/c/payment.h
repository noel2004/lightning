#ifndef LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H
#define LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H

struct Payments;
struct LNchannel;
struct htlc;
struct pubkey;
struct sha256;
struct sha256_double;

/*notify user to pay for the anchor*/
void    lite_anchor_pay_notify(struct Payments *payment, struct LNchannel *lnchn);

/*return 1 for exist managered (our) anchor or 0 for not*/
int     lite_anchor_check(struct Payments *payment, struct sha256_double *txid);

/*return 1 for exist invoice or 0 for not*/
int     lite_invoice_check(struct Payments *payment, const struct sha256* rhash);

void    lite_invoice_resolve(struct Payments *payment, const struct sha256* rhash,
    const struct htlc* invoice_htlc);

enum invoice_status 
{
    INVOICE_RESOLVED,
    INVOICE_CHAIN_FAIL,
    INVOICE_CHAIN_FAIL_TEMP,
};

void    lite_invoice_fail(struct Payments *payment, const struct sha256* rhash,
    enum invoice_status ret);


#endif