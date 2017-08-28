#ifndef LIGHTNING_LITE_C_INTERFACE_MANAGER_H
#define LIGHTNING_LITE_C_INTERFACE_MANAGER_H

struct LNchannels;
struct LNchannel;
struct LNchannelQuery;
struct LNchannelComm;
struct htlc;
struct pubkey;
struct sha256;
struct sha256_double;


/* 
   data needed to be query is updated as transaction
   currently the updated data include:
   * all htlc data (require deep copy), query by hash and source (upstream/downstream)
   * commit_info:txid
*/
void    lite_update_channel(struct LNchannels *mgr, const struct LNchannel *lnchn);


struct LNchannelQuery* lite_query_channel(struct LNchannels *mgr, struct pubkey *id);
struct LNchannelQuery* lite_query_channel_from_htlc(struct LNchannels *mgr, const struct sha256* hash, int issrc);
void    lite_release_chn(struct LNchannels *mgr, const struct LNchannelQuery* chn);

struct LNchannelComm*  lite_comm_channel(struct LNchannels *mgr, struct LNchannelQuery *q);
void lite_release_comm(struct LNchannels *mgr, struct LNchannelComm *c);

/* query a whole HTLC*/
struct htlc *lite_query_htlc_direct(struct LNchannels *mgr, const struct sha256* hash, int issrc);
void    lite_release_htlc(struct LNchannels *mgr, struct htlc *htlc);
/*
   All assigned data MUST be free with tal_free by caller
   A failed (not actived) channel MUST NOT query anything except default value
*/

/* query commit_txid: [local, remote], can be NULL, allocation is responsed by LNchannelQuery*/
void    lite_query_commit_txid(struct LNchannelQuery *q, struct sha256_double *commit_txid[2]);

/* query a HTLC from a channel, should be also released by lite_release_htlc*/
struct htlc *lite_query_htlc(struct LNchannelQuery *q, const struct sha256* hash);

/*
    Actions
*/
void lite_notify_chn_commit(struct LNchannelComm* c);

#endif
