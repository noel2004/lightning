#pragma once
#ifndef LIGHTNING_LITE_DUMMY_IMPL_H
#define LIGHTNING_LITE_DUMMY_IMPL_H

#include <functional>
#include "lightningcore/lnchannel.h"
#include "bitcoin/simple.h"

namespace lnl_dummy {

    class task_package_base
    {
    protected:
        virtual void execute() = 0;
    public:
        virtual ~task_package_base(){}
        void operator()() { execute(); }
    };

    template<class F>
    class task_package : public task_package_base
    {
        F funcobj;
        void execute() override { funcobj(); }

    public:
        task_package(const F& o) : funcobj(o) { }

    };

    void  add_task_p(task_package_base*);
    template<class F>
    void  add_task(const F& o) { add_task_p(new task_package<F>(o)); }

    void  dump_tasks();
    void  clear_tasks();

    struct LNchannel* dummy_get_channel(struct LNchannels *, const struct pubkey *);

}//namespace lnl_dummy



#endif //LIGHTNING_LITE_DUMMY_IMPL_H

