#include "dummy.h"

extern "C" {

#include "btcnetwork/c/chaintopology.h"
#include "btcnetwork/c/watch.h"

}


using namespace lnl_dummy;

extern "C" {

    u32 get_block_height(const struct chain_topology *topo)
    {
        return 0;
    }

    u64 get_feerate(const struct chain_topology *topo)
    {
        return 55u;//a default feerate
    }

}
