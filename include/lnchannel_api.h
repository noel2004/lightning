#ifndef LIGHTNING_CORE_LNCHANNEL_API_H
#define LIGHTNING_CORE_LNCHANNEL_API_H

#ifndef LNCHANNEL_API
# if defined(_WIN32)
#  ifdef _WINDLL
#   define LNCHANNEL_API __declspec(dllexport)
#   define LNCORE_BUILD
#  elif defined(_CONSOLE)
#   define LNCHANNEL_API __declspec(dllimport)
#   define LNCORE_USED
#  else
#   define LNCHANNEL_API
#  endif
# elif defined(__GNUC__) && defined(LNCORE_BUILD)
#  define LNCHANNEL_API __attribute__ ((visibility ("default")))
# else
#  define LNCHANNEL_API
# endif
#endif

#include "bitcoin/simple.h"
#include "lnchannel_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

struct LNcore;
struct LNworkspace;
struct LNchannel;


struct LNAPI_channel_detail_s
{
    const struct LNchannel* chn;
    const struct pubkey *id;
    unsigned long long  balance;
    unsigned long long  ability;
    const struct sha256_double *anchor_txid;
};

LNCHANNEL_API struct LNcore* LNAPI_init();
LNCHANNEL_API void LNAPI_uninit(struct LNcore*);
LNCHANNEL_API struct LNworkspace* LNAPI_assign_workspace(struct LNcore*);
LNCHANNEL_API int LNAPI_release_workspace(struct LNworkspace*);

/*lnchannel.h wrapper*/
//create channel and bind it to a workspace (can rebind)
LNCHANNEL_API int LNAPI_channel_new(struct LNworkspace*, const struct pubkey*);
LNCHANNEL_API int LNAPI_channel_bind(struct LNchannel*, struct LNworkspace*);
LNCHANNEL_API int LNAPI_channel_detail(struct LNAPI_channel_detail_s *);


#ifdef __cplusplus
}
#endif

#endif

