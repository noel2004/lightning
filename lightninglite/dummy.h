#pragma once
#ifndef LIGHTNING_LITE_DUMMY_IMPL_H
#define LIGHTNING_LITE_DUMMY_IMPL_H

#include <future>

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
    class task_package : protected task_package_base
    {
        F funcobj;
        void execute() override { funcobj(); }

    public:
        task_package(F&& o) : funcobj(o){}

    };

    void  add_task(task_package_base*);
    template<class F>
    void  add_task(F&& o) { add_task(new task_package<F>(o)); }

    void  dump_tasks();
    void  clear_tasks();

}//namespace lnl_dummy



#endif //LIGHTNING_LITE_DUMMY_IMPL_H

