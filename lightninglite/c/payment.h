#ifndef LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H
#define LIGHTNING_LITE_C_INTERFACE_PAYMENTS_H

struct Payments;
struct LNchannel;
struct htlc;
struct pubkey;
struct sha256;

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