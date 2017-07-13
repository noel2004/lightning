#ifndef LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H
#define LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H
#include "config.h"
#include "bitcoin/shadouble.h"
#include <ccan/short_types/short_types.h>

struct bitcoin_tx;
struct outsourcing;
struct LNchannel;

enum outsourcing_result {
	OUTSOURCING_OK,
    OUTSOURCING_DENY = -1,    //server unavailiable
    OUTSOURCING_INVALID = -2, //invalid transaction
    OUTSOURCING_FAIL = -3,    //valid transaction but stale
};

/* outsourcing an output from committx*/
struct txowatch {

    struct bitcoin_tx *committx;
    unsigned int index;
    struct bitcoin_tx *delive_tx;

	void (*notify)(enum outsourcing_result, struct sha256_double *delivered_txid, void *cbdata);
	void *cbdata;
};

struct txdeliver {

    struct bitcoin_tx *delive_tx;

    void(*notify)(enum outsourcing_result, struct sha256_double *delivered_txid, void *cbdata);
    void *cbdata;
};

struct txverify {
    struct sha256_double *txid;
    unsigned int depth;
    void(*notify)(enum outsourcing_result, struct sha256_double *txid, void *cbdata);
    void *cbdata;
};

void outsourcing_verify(struct outsourcing* svr, const struct LNchannel* lnchn, const struct sha256_double *txid);
void outsourcing_tx(struct outsourcing* svr, const struct LNchannel* lnchn, const struct txdeliver* w);
void outsourcing_txout(struct outsourcing* svr, const struct LNchannel* lnchn, const struct txowatch* w);

//TODO: a batch update for all outsourcing task should be added 
//TODO: the old fashion watch can be added 


#endif /* LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H */
