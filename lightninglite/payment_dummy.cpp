// #include "dummy.h"

extern "C" {
#include "c/payment.h"


void    lite_anchor_pay_notify(struct Payments *payment, struct LNchannel *lnchn)
{

}

int     lite_anchor_check(struct Payments *payment, struct sha256_double *txid)
{
    return 0;
}

int     lite_invoice_check(struct Payments *payment, const struct sha256* rhash)
{
    return 0;
}

void    lite_invoice_resolve(struct Payments *payment, const struct sha256* rhash,
    const struct htlc* invoice_htlc)
{

}

void    lite_invoice_fail(struct Payments *payment, const struct sha256* rhash,
    enum invoice_status ret)
{

}

}
