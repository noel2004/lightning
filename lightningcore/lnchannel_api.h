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
# elif defined(__GNUC__) && defined(WALLY_CORE_BUILD)
#  define LNCHANNEL_API __attribute__ ((visibility ("default")))
# else
#  define LNCHANNEL_API
# endif
#endif

#include "bitcoin/simple.h"

#ifdef __cplusplus
extern "C" {
#endif

LNCHANNEL_API int LNAPI_u8arr_size(const unsigned char* str);

/*lnchannel.h wrapper*/
LNCHANNEL_API int LNAPI_channel_update_htlc(struct LNchannel *lnchn, const struct sha256 *rhash);
LNCHANNEL_API int LNAPI_channel_do_commit(struct LNchannel *chn);
LNCHANNEL_API int LNAPI_channel_open_anchor(struct LNchannel *lnchn, const unsigned char* txdata,
    unsigned int txdata_sz);

LNCHANNEL_API int LNAPI_channelnotify_open_remote(struct LNchannel *chn,
    const struct pubkey *remotechnid,                
    const struct LNchannel_config *nego_config,
    const struct sha256 *revocation_hash,      
    const struct pubkey *remote_commit_key,
    const struct pubkey *remote_final_key
);
LNCHANNEL_API int LNAPI_channelnotify_anchor(struct LNchannel *chn,
    const struct sha256_double *txid,
    unsigned int index,
    unsigned long long amount,
    const struct sha256 *revocation_hash
);
LNCHANNEL_API int LNAPI_channelnotify_first_commit(struct LNchannel *chn,
    const struct sha256 *revocation_hash,
    const struct ecdsa_signature_ *sig
);
LNCHANNEL_API int LNAPI_channelnotify_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    unsigned int num_htlc_entry,
    const struct msg_htlc_entry *htlc_entry
);
LNCHANNEL_API int LNAPI_channelnotify_remote_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct ecdsa_signature_ *sig,
    const struct sha256 *next_revocation,
    const struct sha256 *revocation_image
);
LNCHANNEL_API int LNAPI_channelnotify_revo_commit(struct LNchannel *chn,
    unsigned long long commit_num,
    const struct sha256 *revocation_image
);
LNCHANNEL_API int LNAPI_channelnotify_commit_done(struct LNchannel *chn);

#ifdef __cplusplus
}
#endif

#endif

