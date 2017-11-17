#include "watch_demo.h"

using namespace lnl_demo;

extern "C" {
#include "btcnetwork/c/watch.h"

    void outsourcing_tasks(struct outsourcing* svr,
        const struct lnwatch_task *tasks, unsigned int taskcnt,//array of tasks
        void(*notify)(enum outsourcing_result, void *cbdata),
        void *cbdata
    ) {
        auto p = static_cast<outsourcing_impl*>(svr);
        p->add_task(std::bind(
            notify,
            OUTSOURCING_OK,
            cbdata
        ));
    }

    void outsourcing_verifytask(struct outsourcing* svr,
        const struct lnwatch_verifytask *tasks, unsigned int taskcnt,//array of tasks
        void(*notify)(enum outsourcing_result, void *cbdata),
        void *cbdata
    ) {
        auto p = static_cast<outsourcing_impl*>(svr);
        p->add_task(std::bind(
            notify,
            OUTSOURCING_OK,
            cbdata
        ));
    }

    void outsourcing_task_clear(struct outsourcing* svr, const struct sha256_double* commitid)
    {

    }

}

