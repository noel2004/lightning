#include "watch.h"
#include <string.h>

void outsourcing_task_init(struct lnwatch_task* task, const struct sha256_double* commitid)
{
    task->tasktype = OUTSOURCING_PASSIVE;
    memcpy(&task->commitid, commitid, sizeof(task->commitid));
    task->preimage = NULL;
    task->htlctxs = NULL;
    task->trigger_tx = NULL;
    task->trigger_deadline = NULL;
    task->redeem_tx = NULL;
}

void outsourcing_htlctask_init(struct lnwatch_htlc_task* task, const struct sha256* rhash)
{
    memcpy(&task->rhash, rhash, sizeof(task->rhash));
    task->txdeliver = NULL;
    task->txowatchs = NULL;
    task->r = NULL;
}
