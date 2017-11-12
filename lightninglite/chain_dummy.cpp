#include "dummy.h"

extern "C" {

#include "btcnetwork/c/chaintopology.h"
#include "btcnetwork/c/watch.h"

    u32 get_block_height(const struct chain_topology *topo)
    {
        return 0;
    }

    u64 get_feerate(const struct chain_topology *topo)
    {
        return 0;
    }

    struct chain_topology
    {

    };

    struct outsourcing
    {

    };
}

namespace lnl_dummy {

    

    class btcnewtork_dummy : 
        public chain_topology, public outsourcing
    {

    };

    void    btcnetwork_init(struct lightningd_state* state)
    {
        auto p = new btcnewtork_dummy;
        state->topology = p;
        state->outsourcing_svr = p;
    }

    void    btcnetwork_release(struct lightningd_state* state)
    {
        auto p = static_cast<btcnewtork_dummy*>(state->topology);
        delete p;
        state->topology = nullptr;
        state->outsourcing_svr = nullptr;
    }


}