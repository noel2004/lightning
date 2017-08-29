#ifndef LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H
#define LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H
#include "config.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/signature.h"
#include <ccan/short_types/short_types.h>

struct bitcoin_tx;
struct outsourcing;
struct preimage;

enum outsourcing_tasktype {
    OUTSOURCING_PASSIVE,
    OUTSOURCING_AGGRESSIVE,
    OUTSOURCING_UPDATE,
    OUTSOURCING_RESOLVED, //a resolved task never accept more update, and remove all watching task 
};

enum outsourcing_result {
	OUTSOURCING_OK,
    OUTSOURCING_DENY = -1,    //server unavailiable
    OUTSOURCING_INVALID = -2, //invalid transaction
    OUTSOURCING_FAIL = -3,    //valid transaction but stale
};

/* 
    outsourcing an output for htlc from committx, if correspondig output is redeemed,
    it should try to takeout the preimage
*/
struct txowatch {
    struct sha256_double commitid;
    size_t output_num;
};

struct txdeliver {
    const struct bitcoin_tx *deliver_tx;

    /* data to build witness */
    u8 *wscript;

    /* preimage */
    struct preimage *r;

    /* lock-time must be clear to apply this signature*/
    ecdsa_signature *sig_nolocked;

    /* sign with lock-time, no needed for "their" HTLC */
    ecdsa_signature *sig;
};

struct lnwatch_htlc_task {
    struct sha256 rhash;

    struct txdeliver *txdeliver;    

    /* additional trigger */
    struct txowatch *txowatchs; 
    u8 txowatch_num;
};

struct lnwatch_task {

    enum outsourcing_tasktype tasktype;

    /* txid which may be broadcasted from other side*/
    struct sha256_double commitid;

    /* the tx needed to be trigger and broadcasted by txowatch task in aggresive mode*/
    const struct bitcoin_tx *trigger_tx;

    /* the revocation preimage used in htlctxs/redeem_tx */
    struct sha256* preimage;

    /* if delivered by us, required additional tx to redeem the delayed part*/
    /* if delivered by theirs and is up-to-date, no action is needed except the htlc part */
    struct txdeliver *redeem_tx;

    /* if specifed, must be trigger after deadline even no txowatch */
    u32* trigger_deadline;

    /* htlcs we sent and should try to redeem if it is expired*/
    struct lnwatch_htlc_task* htlctxs;
};

/* a verify-only task, finished if corresponding txid reach expected depth*/
struct lnwatch_verifytask {
    struct sha256_double *txid;
    unsigned int depth;
};

void outsourcing_task_init(struct lnwatch_task* task, const struct sha256_double* commitid);

void outsourcing_htlctask_init(struct lnwatch_htlc_task* task, const struct sha256* rhash);

/* 
   task with same commitid will be updated (e.g. switch a commit from up-to-date to expired) 
   any member is not NULL will be replaced while NULL members is just omited (not deleted)
*/
void outsourcing_tasks(struct outsourcing* svr,  
    const struct lnwatch_task *tasks, unsigned int taskcnt,//array of tasks
    void(*notify)(enum outsourcing_result, void *cbdata),
    void *cbdata
    );

void outsourcing_verifytask(struct outsourcing* svr,
    const struct lnwatch_verifytask *tasks, unsigned int taskcnt,//array of tasks
    void(*notify)(enum outsourcing_result, void *cbdata),
    void *cbdata
    );

/* clear corresponding task */
void outsourcing_task_clear(struct outsourcing* svr, const struct sha256_double* commitid);

//TODO: a batch update for all outsourcing task should be added 
//TODO: the old fashion watch can be added 


#endif /* LIGHTNING_BTCNETWORK_OUTSOURCING_C_INTERFACE_H */
