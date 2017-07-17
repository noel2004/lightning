#ifndef LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H
#define LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H
#include "config.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include <ccan/short_types/short_types.h>
#include <ccan/crypto/sha256/sha256.h>

struct bitcoin_tx;
struct outsourcing;
struct LNchannel;

enum outsourcing_result {
	OUTSOURCING_OK,
    OUTSOURCING_DENY = -1,    //server unavailiable
    OUTSOURCING_INVALID = -2, //invalid transaction
    OUTSOURCING_FAIL = -3,    //valid transaction but stale
};

struct witnessgroup
{
    u8 *wscript;
    ecdsa_signature sig;
};

/* outsourcing an output for htlc from committx*/
struct txowatch {
    struct bitcoin_tx *committx;
    u8 *outscript;
};

struct txdeliver {
    /* can be resolved by a pending txo */
    struct txowatch *wait_txo;
    /* can be resolved after locktime */
    unsigned int lockeddepth;
    /* data required for broadcasting tx*/
    struct witnessgroup witness;

    struct bitcoin_tx *deliver_tx;
};

struct lnwatch_task {

    /* txid which may be broadcasted from other side*/
    struct sha256_double *commitid;

    /* if NULL, can be expried by later call*/
    struct sha256* preimage;

    /* if delivered by us, required additional tx to redeem the delayed part*/
    /* if delivered by theirs and is up-to-date, no action is needed except the htlc part */
    struct txdeliver *redeem_tx;

    /* htlcs we sent and should try to redeem if it is expired*/
    struct txdeliver* htlctxs;
};

/* a verify-only task, finished if corresponding txid reach expected depth*/
struct lnwatch_verifytask {
    struct sha256_double *txid;
    unsigned int depth;
};

/* create or sync outsourcing task */
void outsourcing_initchannel(struct outsourcing* svr, const struct LNchannel* lnchn);

/* clear corresponding task */
void outsourcing_clear(struct outsourcing* svr, const struct LNchannel* lnchn);

/* 
   task with same commitid will be updated (e.g. switch a commit from up-to-date to expired) 
   any member is not NULL will be replaced while NULL members is just omited (not deleted)
*/
void outsourcing_task(struct outsourcing* svr, const struct LNchannel* lnchn, 
    const struct lnwatch_task *task, 
    void(*notify)(enum outsourcing_result, struct sha256_double *ctxid, void *cbdata),
    void *cbdata
    );

void outsourcing_verifytask(struct outsourcing* svr, const struct LNchannel* lnchn, 
    const struct lnwatch_verifytask *task, 
    void(*notify)(enum outsourcing_result, struct sha256_double *txid, void *cbdata),
    void *cbdata
    );

//TODO: a batch update for all outsourcing task should be added 
//TODO: the old fashion watch can be added 


#endif /* LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H */
