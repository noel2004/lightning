#pragma once
#ifndef LIGHTNING_LITE_WATCH_DEMO_IMPL_H
#define LIGHTNING_LITE_WATCH_DEMO_IMPL_H

#include <functional>
#include <list>

#ifdef __cplusplus
extern "C" {
#endif
    struct outsourcing {};

#ifdef __cplusplus
}
#endif

namespace lnl_demo {

    class task_package_base
    {
    protected:
        virtual void execute() = 0;
    public:
        virtual ~task_package_base() {}
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

    class outsourcing_impl : public ::outsourcing
    {
        std::list<task_package_base*> task_list;
        void  add_task_p(task_package_base* p) { task_list.push_back(p); }
    public:
        template<class F>
        void  add_task(const F& o) { add_task_p(new task_package<F>(o)); }
        void  execute();
        void  clear_tasks();
    };

}

#endif //LIGHTNING_LITE_WATCH_DEMO_IMPL_H