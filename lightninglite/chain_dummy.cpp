#include "dummy.h"

extern "C" {
#include "lightningcore/state.h"
#include "btcnetwork/c/chaintopology.h"

    u32 get_block_height(const struct chain_topology *topo)
    {
        return 0;
    }

    u64 get_feerate(const struct chain_topology *topo)
    {
        return 0;
    }
}

namespace lnl_dummy {


}