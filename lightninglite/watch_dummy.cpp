#include "dummy.h"

extern "C" {
#include "lightningcore/state.h"
#include "btcnetwork/c/watch.h"

    struct outsourcing
    {

    };

    void outsourcing_tasks(struct outsourcing* svr,
        const struct lnwatch_task *tasks, unsigned int taskcnt,//array of tasks
        void(*notify)(enum outsourcing_result, void *cbdata),
        void *cbdata
    ) {
        lnl_dummy::add_task(std::bind(
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
        lnl_dummy::add_task(std::bind(
            notify,
            OUTSOURCING_OK,
            cbdata
        ));
    }

    void outsourcing_task_clear(struct outsourcing* svr, const struct sha256_double* commitid)
    {

    }

}

namespace lnl_dummy {

    void init_watch(struct lightningd_state* state) {
        state->outsourcing_svr = new struct outsourcing;
    }

    void clean_watch(struct lightningd_state* state) {
        delete state->outsourcing_svr;
    }
}