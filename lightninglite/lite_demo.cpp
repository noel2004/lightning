#include "lite_demo.h"

extern "C"{

void    lite_init(struct lightningd_state* state)
{
    auto p = new lnl_demo::LNlite;
    p->alloc_ctx = p->state = state;
    state->channels = p;
    state->message_svr = p;
    state->payment = p;
}

void    lite_clean(struct lightningd_state* state)
{
    auto p = static_cast<lnl_demo::LNlite*>(state->channels);
    delete p;
    state->channels = nullptr;
    state->message_svr = nullptr;
    state->payment = nullptr;
}

void    btcnetwork_init(struct lightningd_state* state)
{
    auto p = new lnl_demo::btcnewtork;
    state->topology = p;
    state->outsourcing_svr = p;
}

void    btcnetwork_release(struct lightningd_state* state)
{
    auto p = static_cast<lnl_demo::btcnewtork*>(state->topology);
    delete p;
    state->topology = nullptr;
    state->outsourcing_svr = nullptr;
}

}