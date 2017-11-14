#include "include/lnchannel_api.h"
#include "lnchannel_internal.h"
#include "log.h"
#include "db.h"
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>


struct LNcore
{
    struct lightningd_state *dstate_sample;
    u32    workspace_num;
};

struct LNworkspace
{
    struct lightningd_state *dstate;
};

LNCHANNEL_API struct LNcore* LNAPI_init()
{
    struct LNcore *core = tal(NULL, struct LNcore);
    struct lightningd_state *dstate = talz(core, struct lightningd_state);

    lite_init(dstate);
    btcnetwork_init(dstate);

    log_info(dstate->base_log, "Hello world!");

    dstate->testnet = true;
    dstate->default_redeem_address = NULL;
 
    core->dstate_sample = dstate;

    return core;

}

LNCHANNEL_API void LNAPI_uninit(struct LNcore* pcore)
{
    tal_free(pcore);
}

LNCHANNEL_API struct LNworkspace* LNAPI_assign_workspace(struct LNcore* pcore)
{
    struct LNworkspace *ws = tal(pcore, struct LNworkspace);
    struct lightningd_state *dstate = tal_dup(ws, struct lightningd_state, pcore->dstate_sample);

    ws->dstate = dstate;
    //dstate in workspace use same lite and btc-network implement, but separated log and db entry
    //TODO: bind destructor for dstate

    dstate->log_book = new_log_book(dstate, 20 * 1024 * 1024, LOG_INFORM);
    dstate->base_log = new_log(dstate, dstate->log_book,
        "lightning-lite(%u):", pcore->workspace_num);
    db_init(dstate);

    pcore->workspace_num++;

    return ws;
}

LNCHANNEL_API int LNAPI_release_workspace(struct LNworkspace* ws)
{
    //TODO: clear db and log ...

    tal_free(ws);
    return 0;
}

static     int check_failure(struct LNchannel *lnchn)
{
    return 0;
}

