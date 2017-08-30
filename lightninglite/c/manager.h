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


struct LNchannelQuery* lite_query_channel(struct LNchannels *mgr, const struct pubkey *id);
struct LNchannelQuery* lite_query_channel_from_htlc(struct LNchannels *mgr, const struct sha256* hash, int issrc);
void    lite_release_chn(struct LNchannels *mgr, const struct LNchannelQuery* chn);

struct LNchannelComm*  lite_comm_channel(struct LNchannels *mgr, struct LNchannelQuery *q);
struct LNchannelComm* lite_comm_channel_from_htlc(struct LNchannels *mgr, const struct sha256* hash, int issrc);
void lite_release_comm(struct LNchannels *mgr, struct LNchannelComm *c);

/* query a whole HTLC*/
const struct htlc *lite_query_htlc_direct(struct LNchannels *mgr, const struct sha256* hash, int issrc);
void    lite_release_htlc(struct LNchannels *mgr, const struct htlc *htlc);
/*
   All allocation in query is responsed by LNchannelQuery
*/

/* 
   query commit_txid: [local, remote, <previous remote>], can be NULL, 
   previous remote only exist when channel is under commting state   
*/
void    lite_query_commit_txid(const struct LNchannelQuery *q, struct sha256_double *commit_txid[3]);

const struct pubkey *lite_query_pubkey(const struct LNchannelQuery *q);

/* 0 indicate normal (active) and other is for different cases*/
int lite_query_isactive(const struct LNchannelQuery *q);

const struct sha256_double *lite_query_anchor_txid(const struct LNchannelQuery *q);
/* query a HTLC from a channel, should be also released by lite_release_htlc*/
const struct htlc *lite_query_htlc(const struct LNchannelQuery *q, const struct sha256* hash);

/*
    Actions
*/
void lite_notify_chn_commit(struct LNchannelComm* c);


#endif
