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

struct LNchannel;

struct LNAPI_channel_detail
{
    const struct pubkey *id;
    unsigned long long  balance;
    unsigned long long  ability;
    const struct sha256_double *anchor_txid;
};

LNCHANNEL_API const struct pubkey*  LNAPI_channel_pubkey(const struct LNchannel*);
LNCHANNEL_API int                   LNAPI_channel_state(const struct LNchannel*);
LNCHANNEL_API unsigned long long    LNAPI_channel_balance(const struct LNchannel*);
LNCHANNEL_API unsigned long long    LNAPI_channel_ability(const struct LNchannel*);
LNCHANNEL_API const struct sha256_double* LNAPI_channel_anchor_txid(struct LNchannel *lnchn);

/*lnchannel.h wrapper*/
LNCHANNEL_API int LNAPI_channel_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash);
LNCHANNEL_API int LNAPI_channel_do_commit(struct LNchannel *chn);
LNCHANNEL_API int LNAPI_channel_open_anchor(struct LNchannel *lnchn, const unsigned char* txdata,
    unsigned int txdata_sz);



#ifdef __cplusplus
}
#endif

#endif

