#ifndef LIGHTNING_DAEMON_STATE_H
#define LIGHTNING_DAEMON_STATE_H
#include "config.h"

#include "state_types.h"
#include <stdbool.h>

#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/timer/timer.h>
#include <stdio.h>

struct LNchannels;

/* Various adjustable things. */
struct config {
    /* How long do we want them to lock up their funds? (blocks) */
    u32 locktime_blocks;

    /* How long do we let them lock up our funds? (blocks) */
    u32 locktime_max;

    /* How many blocks before we expect to see anchor?. */
    u32 anchor_onchain_wait;

    /* How many confirms until we consider an anchor "settled". */
    u32 anchor_confirms;

    /* How long will we accept them waiting? */
    u32 anchor_confirms_max;

    /* How many blocks until we stop watching a close commit? */
    u32 forever_confirms;

    /* Maximum percent of fee rate we'll accept. */
    u32 commitment_fee_max_percent;

    /* Minimum percent of fee rate we'll accept. */
    u32 commitment_fee_min_percent;

    /* Percent of fee rate we'll use. */
    u32 commitment_fee_percent;

    /* Minimum/maximum time for an expiring HTLC (blocks). */
    u32 min_htlc_expiry, max_htlc_expiry;

    /* How many blocks before upstream HTLC expiry do we panic and dump? */
    u32 deadline_blocks;

    /* Fee rates. */
    u32 fee_base;
    s32 fee_per_satoshi;

    /* How long between polling bitcoind. */
    struct timerel poll_time;

    /* How long between changing commit and sending COMMIT message. */
    struct timerel commit_time;

    /* Whether to ignore database version. */
    bool db_version_ignore;

};

/* Here's where the global variables hide! */
struct lightningd_state {
    /* Where all our logging goes. */
    struct log_book *log_book;
    struct log *base_log;
    FILE *logf;

    /* Our config dir, and rpc file */
    char *config_dir;

    /* A default redeem address*/
    char *default_redeem_address;

    /* We're on testnet. */
    bool testnet;

    /* Configuration settings. */
    struct config config;

    /* The database where we keep our stuff. */
    struct db *db;

    /* Cached block topology. */
    struct chain_topology *topology;

    /* Manager for payments*/
    struct Payments *payment;

    /* Channel manager register interface*/
    struct LNchannels *channels;

    /* Server for out-sourcing transactions*/
    struct outsourcing *outsourcing_svr;

    /* Server for sending message (mostly-once or at least once, according to the API)*/
    struct LNmessage *message_svr;

    ///* Our private key for communication and peer identify*/
    //struct privkey *privkey;

    ///* This is us. */
    //struct pubkey id;

    /* Re-exec hack for testing. */
    char **reexec;

    /* Announce timer. */
    struct oneshot *announce;
};

static inline bool state_is_error(enum state s)
{
	return s >= STATE_ERR_BREAKDOWN && s <= STATE_ERR_INTERNAL;
}

static inline bool state_is_shutdown(enum state s)
{
	return s == STATE_SHUTDOWN || s == STATE_SHUTDOWN_COMMITTING;
}

static inline bool state_is_onchain(enum state s)
{
	return s >= STATE_CLOSE_ONCHAIN_CHEATED
		&& s <= STATE_CLOSE_ONCHAIN_MUTUAL;
}

static inline bool state_is_normal(enum state s)
{
	return s == STATE_NORMAL || s == STATE_NORMAL_COMMITTING;
}

static inline bool state_is_waiting_for_anchor(enum state s)
{
	return s == STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE
		|| s == STATE_OPEN_WAIT_ANCHORDEPTH;
}

static inline bool state_is_openwait(enum state s)
{
	return s == STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE
		|| s == STATE_OPEN_WAIT_ANCHORDEPTH
		|| s == STATE_OPEN_WAIT_THEIRCOMPLETE;
}

static inline bool state_is_opening(enum state s)
{
	return s <= STATE_OPEN_WAIT_THEIRCOMPLETE;
}

//static inline bool state_can_io(enum state s)
//{
//	if (state_is_error(s))
//		return false;
//	if (s == STATE_CLOSED)
//		return false;
//	if (state_is_onchain(s))
//		return false;
//	return true;
//}

static inline bool state_can_commit(enum state s)
{
	return s == STATE_NORMAL || s == STATE_SHUTDOWN;
}

/* FIXME-OLD #2:
 *
 * A node MUST NOT send a `update_add_htlc` after a `close_shutdown`
 */
static inline bool state_can_add_htlc(enum state s)
{
	return state_is_normal(s);
}

static inline bool state_can_remove_htlc(enum state s)
{
	return state_is_normal(s) || state_is_shutdown(s);
}

#endif /* LIGHTNING_STATE_H */
