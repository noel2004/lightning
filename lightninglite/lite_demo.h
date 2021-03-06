#pragma once
#ifndef LIGHTNING_LITE_DEMO_IMPL_H
#define LIGHTNING_LITE_DEMO_IMPL_H

#include "manager_st.h"
#include "message_demo.h"
#include "payment_st.h"
#include "watch_demo.h"

#ifdef __cplusplus
extern "C" {
#endif

    struct lightningd_state;
    struct chain_topology {};

#ifdef __cplusplus
}
#endif

namespace lnl_demo {

    class LNlite : public lnl_st::LNchannels_impl, 
        public lnl_st::Payments_impl, public lnl_demo::LNmessage_impl
    {
    public:
        struct lightningd_state* dstate;
    };

    class btcnewtork :
        public chain_topology, public lnl_demo::outsourcing_impl
    {

    };

}

#endif //LIGHTNING_LITE_DEMO_IMPL_H


