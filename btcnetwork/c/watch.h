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

/* outsourcing an output for htlc from committx*/
struct txowatch {

    struct bitcoin_tx *committx;
    unsigned int index;
    struct bitcoin_tx *deliver_tx;

};

struct txdeliver {
    struct bitcoin_tx *deliver_tx;
    unsigned int lockeddepth;
};

struct lnwatch_task_htlcs {

    /* htlcs we received and should try to redeem if its downstream do so*/
    struct txowatch* htlctx_theirs; 

    /* htlcs we sent and should try to redeem if it is expired*/
    struct txdeliver* htlctx_ours;

};

struct lnwatch_task {

    /* txid which may be broadcasted from other side*/
    struct sha256 commitid;

    /* if delivered by us, required additional tx to redeem the delayed part*/
    /* if delivered by theirs and is up-to-date, no action is needed except the htlc part */
    /* can update the breach tx after the commit is outdated */
    struct txdeliver *redeem_tx;

    /* can be NULL */
    struct lnwatch_task_htlcs *htlcs;
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
   task with same commitid will be updated (switch a commit from up-to-date to expired) 
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
