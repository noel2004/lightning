

extern "C" {

#include "btcnetwork/c/chaintopology.h"

    u32 get_block_height(const struct chain_topology *topo)
    {
        return 20171106;//fixed height
    }

    u64 get_feerate(const struct chain_topology *topo)
    {
        return 55u;//a default feerate
    }


}


