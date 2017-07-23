#include "bitcoin/pullpush.h"
#include "bitcoin/preimage.h"
#include "bitcoin/address.h"
#include "commit_tx.h"
#include "db.h"
#include "feechange.h"
#include "gen_version.h"
#include "htlc.h"
#include "state.h"
#include "names.h"
#include "log.h"
#include "lnchannel_internal.h"
#include "secrets.h"
#include "utils/utils.h"
#include "lightninglite/c/manager.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/cppmagic/cppmagic.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <unistd.h>

#define DB_FILE "lightning.core.sqlite3"

/* They don't use stdint types. */
#define PRIuSQLITE64 "llu"

struct db {
	bool in_transaction;
	const char *err;
	sqlite3 *sql;
};

static void close_db(struct db *db)
{
	sqlite3_close(db->sql);
}

/* We want a string, not an 'unsigned char *' thanks! */
static const char *sqlite3_column_str(sqlite3_stmt *stmt, int iCol)
{
	return cast_signed(const char *, sqlite3_column_text(stmt, iCol));
}

#define SQL_U64(var)		stringify(var)" BIGINT" /* Actually, an s64 */
#define SQL_U32(var)		stringify(var)" INT"
#define SQL_BOOL(var)		stringify(var)" BOOLEAN"
#define SQL_BLOB(var)		stringify(var)" BLOB"

#define SQL_PUBKEY(var)		stringify(var)" CHAR(33)"
#define SQL_PRIVKEY(var)	stringify(var)" CHAR(32)"
#define SQL_SIGNATURE(var)	stringify(var)" CHAR(64)"
#define SQL_TXID(var)		stringify(var)" CHAR(32)"
#define SQL_RHASH(var)		stringify(var)" CHAR(32)"
#define SQL_SHA256(var)		stringify(var)" CHAR(32)"
#define SQL_R(var)		stringify(var)" CHAR(32)"
/* STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE == 45*/
#define SQL_STATENAME(var)	stringify(var)" VARCHAR(45)"
#define SQL_INVLABEL(var)	stringify(var)" VARCHAR("stringify(INVOICE_MAX_LABEL_LEN)")"

/* 8 + 4 + (8 + 32) * (64 + 1) */
#define SHACHAIN_SIZE	2612
#define SQL_SHACHAIN(var)	stringify(var)" CHAR("stringify(SHACHAIN_SIZE)")"

/* FIXME: Should be fixed size. */
#define SQL_ROUTING(var)	stringify(var)" BLOB"
#define SQL_FAIL(var)		stringify(var)" BLOB"

#define TABLE(tablename, ...)					\
	"CREATE TABLE " #tablename " (" CPPMAGIC_JOIN(", ", __VA_ARGS__) ");"

static const char *sql_bool(bool b)
{
	/* SQL2003 says TRUE and FALSE are binary literal keywords.
	 * sqlite3 barfs. */
	return (b) ? "1" : "0";
}

static bool PRINTF_FMT(3,4)
	db_exec(const char *caller,
		struct lightningd_state *dstate, const char *fmt, ...)
{
	va_list ap;
	char *cmd, *errmsg;
	int err;

	if (dstate->db->in_transaction && dstate->db->err)
		return false;

	va_start(ap, fmt);
	cmd = tal_vfmt(dstate->db, fmt, ap);
	va_end(ap);

	err = sqlite3_exec(dstate->db->sql, cmd, NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		tal_free(dstate->db->err);
		dstate->db->err = tal_fmt(dstate->db, "%s:%s:%s:%s",
					  caller, sqlite3_errstr(err),
					  cmd, errmsg);
		sqlite3_free(errmsg);
		tal_free(cmd);
		log_broken(dstate->base_log, "%s", dstate->db->err);
		return false;
	}
	tal_free(cmd);
	return true;
}

static char *sql_hex_or_null(const tal_t *ctx, const void *buf, size_t len)
{
	char *r;

	if (!buf)
		return "NULL";
	r = tal_arr(ctx, char, 3 + hex_str_size(len));
	r[0] = 'x';
	r[1] = '\'';
	hex_encode(buf, len, r+2, hex_str_size(len));
	r[2+hex_str_size(len)-1] = '\'';
	r[2+hex_str_size(len)] = '\0';
	return r;
}

static void from_sql_blob(sqlite3_stmt *stmt, int idx, void *p, size_t n)
{
	if (sqlite3_column_bytes(stmt, idx) != n)
		fatal("db:wrong bytes %i not %zu",
		      sqlite3_column_bytes(stmt, idx), n);
	memcpy(p, sqlite3_column_blob(stmt, idx), n);
}

static u8 *tal_sql_blob(const tal_t *ctx, sqlite3_stmt *stmt, int idx)
{
	u8 *p;

	if (sqlite3_column_type(stmt, idx) == SQLITE_NULL)
		return NULL;

	p = tal_arr(ctx, u8, sqlite3_column_bytes(stmt, idx));
	from_sql_blob(stmt, idx, p, tal_count(p));
	return p;
}

static void address_from_sql(sqlite3_stmt *stmt, int idx, struct bitcoin_address *addr)
{
    int len = sqlite3_column_bytes(stmt, idx);

    if (len == sizeof(addr->addr)) {
        memcpy(addr->addr, sqlite3_column_blob(stmt, idx), len);
    }
    else {
        fatal("db:bad address length %i", len);
    }
}

static void pubkey_from_sql(sqlite3_stmt *stmt, int idx, struct pubkey *pk)
{
    int len = sqlite3_column_bytes(stmt, idx);

    if (len == sizeof(pk->pubkey.data)) {
        memcpy(pk->pubkey.data, sqlite3_column_blob(stmt, idx), len);
    }
    else if (len == sizeof(pk->pubkey.data_uc)) {
        memcpy(pk->pubkey.data_uc, sqlite3_column_blob(stmt, idx), len);
    }
    else {
        fatal("db:bad pubkey length %i", len);
    }
}

static void sha256_from_sql(sqlite3_stmt *stmt, int idx, struct sha256 *sha)
{
	from_sql_blob(stmt, idx, sha, sizeof(*sha));
}

static void sig_from_sql(sqlite3_stmt *stmt, int idx,
			 ecdsa_signature *sig)
{
	from_sql_blob(stmt, idx, sig->data, sizeof(sig->data));

}

static char *sig_to_sql(const tal_t *ctx,
			const ecdsa_signature *sig)
{
	if (!sig)
		return sql_hex_or_null(ctx, NULL, 0);

	return sql_hex_or_null(ctx, sig->data, sizeof(sig->data));
}

//static void db_load_wallet(struct lightningd_state *dstate)
//{
//	int err;
//	sqlite3_stmt *stmt;
//
//	err = sqlite3_prepare_v2(dstate->db->sql, "SELECT * FROM wallet;", -1,
//				 &stmt, NULL);
//
//	if (err != SQLITE_OK)
//		fatal("db_load_wallet:prepare gave %s:%s",
//		      sqlite3_errstr(err), sqlite3_errmsg(dstate->db->sql));
//
//	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
//		struct privkey privkey;
//		if (err != SQLITE_ROW)
//			fatal("db_load_wallet:step gave %s:%s",
//			      sqlite3_errstr(err),
//			      sqlite3_errmsg(dstate->db->sql));
//		if (sqlite3_column_count(stmt) != 1)
//			fatal("db_load_wallet:step gave %i cols, not 1",
//			      sqlite3_column_count(stmt));
//		from_sql_blob(stmt, 0, &privkey, sizeof(privkey));
//		if (!restore_wallet_address(dstate, &privkey))
//			fatal("db_load_wallet:bad privkey");
//	}
//	err = sqlite3_finalize(stmt);
//	if (err != SQLITE_OK)
//		fatal("db_load_wallet:finalize gave %s:%s",
//		      sqlite3_errstr(err),
//		      sqlite3_errmsg(dstate->db->sql));
//}

//void db_add_wallet_privkey(struct lightningd_state *dstate,
//			   const struct privkey *privkey)
//{
//	char *ctx = tal_tmpctx(dstate);
//
//	log_debug(dstate->base_log, "%s", __func__);
//	if (!db_exec(__func__, dstate,
//		      "INSERT INTO wallet VALUES (x'%s');",
//		     tal_hexstr(ctx, privkey, sizeof(*privkey))))
//		fatal("db_add_wallet_privkey failed");
//	tal_free(ctx);
//}

static void load_lnchn_secrets(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	const char *select;
	bool secrets_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM lnchn_secrets WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_secrets:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_lnchn_secrets:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		if (secrets_set)
			fatal("load_lnchn_secrets: two secrets for '%s'",
			      select);
		lnchn_set_secrets_from_db(lnchn,
					 sqlite3_column_blob(stmt, 1),
					 sqlite3_column_bytes(stmt, 1),
					 sqlite3_column_blob(stmt, 2),
					 sqlite3_column_bytes(stmt, 2),
					 sqlite3_column_blob(stmt, 3),
					 sqlite3_column_bytes(stmt, 3));
		secrets_set = true;
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_visible_state:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	if (!secrets_set)
		fatal("load_lnchn_secrets: no secrets for '%s'", select);
	tal_free(ctx);
}

static void load_lnchn_anchor(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	const char *select;
	bool anchor_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM anchors WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_anchor:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_lnchn_anchor:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		if (anchor_set)
			fatal("load_lnchn_anchor: two anchors for '%s'",
			      select);
		from_sql_blob(stmt, 1,
			      &lnchn->anchor.txid, sizeof(lnchn->anchor.txid));
		lnchn->anchor.index = sqlite3_column_int64(stmt, 2);
		lnchn->anchor.satoshis = sqlite3_column_int64(stmt, 3);
		lnchn->anchor.ours = sqlite3_column_int(stmt, 6);
//		lnchn_watch_anchor(lnchn, sqlite3_column_int(stmt, 4));
		lnchn->anchor.min_depth = sqlite3_column_int(stmt, 5);
		anchor_set = true;
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_visible_state:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	if (!anchor_set)
		fatal("load_lnchn_anchor: no anchor for '%s'", select);
	tal_free(ctx);
}

static void load_lnchn_anchor_input(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	const char *select;
	bool anchor_input_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM anchor_inputs WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_anchor_input:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_lnchn_anchor_input:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		if (anchor_input_set)
			fatal("load_lnchn_anchor_input: two inputs for '%s'",
			      select);
		lnchn->anchor.input = tal(lnchn, struct anchor_input);
		from_sql_blob(stmt, 1,
			      &lnchn->anchor.input->txid,
			      sizeof(lnchn->anchor.input->txid));
		lnchn->anchor.input->index = sqlite3_column_int(stmt, 2);
		lnchn->anchor.input->in_amount = sqlite3_column_int64(stmt, 3);
		lnchn->anchor.input->out_amount = sqlite3_column_int64(stmt, 4);
		pubkey_from_sql(stmt, 5, &lnchn->anchor.input->walletkey);
		anchor_input_set = true;
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_visible_state:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	if (!anchor_input_set)
		fatal("load_lnchn_anchor_input: no inputs for '%s'", select);
	tal_free(ctx);
}

static void load_lnchn_visible_state(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	const char *select;
	bool visible_set = false;

	select = tal_fmt(ctx,
			 "SELECT * FROM their_visible_state WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_visible_state:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_lnchn_visible_state:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 8)
			fatal("load_lnchn_visible_state:step gave %i cols, not 8",
			      sqlite3_column_count(stmt));

		if (visible_set)
			fatal("load_lnchn_visible_state: two states for %s", select);
		visible_set = true;

		lnchn->remote.offer_anchor = sqlite3_column_int(stmt, 1);
		pubkey_from_sql(stmt, 2, &lnchn->remote.commitkey);
		pubkey_from_sql(stmt, 3, &lnchn->remote.finalkey);
		lnchn->remote.locktime.locktime = sqlite3_column_int(stmt, 4);
		lnchn->remote.mindepth = sqlite3_column_int(stmt, 5);
		lnchn->remote.commit_fee_rate = sqlite3_column_int64(stmt, 6);
		sha256_from_sql(stmt, 7, &lnchn->remote.next_revocation_hash);
		log_debug(lnchn->log, "%s:next_revocation_hash=%s",
			  __func__,
			  tal_hexstr(ctx, &lnchn->remote.next_revocation_hash,
				     sizeof(lnchn->remote.next_revocation_hash)));

		/* Now we can fill in anchor witnessscript. */
		lnchn->anchor.witnessscript
			= bitcoin_redeem_2of2(lnchn,
					      &lnchn->local.commitkey,
					      &lnchn->remote.commitkey);
	}

	if (!visible_set)
		fatal("load_lnchn_visible_state: no result '%s'", select);

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_visible_state:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));
	tal_free(ctx);
}

static void load_lnchn_commit_info(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT * FROM commit_info WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_commit_info:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct commit_info **cip, *ci;

		if (err != SQLITE_ROW)
			fatal("load_lnchn_commit_info:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		/* lnchn "SQL_PUBKEY", side TEXT, commit_num INT, revocation_hash "SQL_SHA256", sig "SQL_SIGNATURE", xmit_order INT, prev_revocation_hash "SQL_SHA256",  */
		if (sqlite3_column_count(stmt) != 7)
			fatal("load_lnchn_commit_info:step gave %i cols, not 7",
			      sqlite3_column_count(stmt));

		if (streq(sqlite3_column_str(stmt, 1), "LOCAL"))
			cip = &lnchn->local.commit;
		else {
			if (!streq(sqlite3_column_str(stmt, 1), "REMOTE"))
				fatal("load_lnchn_commit_info:bad side %s",
				      sqlite3_column_str(stmt, 1));
			cip = &lnchn->remote.commit;
			/* This is a hack where we temporarily store their
			 * previous revocation hash before we get their
			 * revocation. */
			if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
				lnchn->their_prev_revocation_hash
					= tal(lnchn, struct sha256);
				sha256_from_sql(stmt, 6,
						lnchn->their_prev_revocation_hash);
			}
		}

		/* Do we already have this one? */
		if (*cip)
			fatal("load_lnchn_commit_info:duplicate side %s",
			      sqlite3_column_str(stmt, 1));

		*cip = ci = new_commit_info(lnchn, sqlite3_column_int64(stmt, 2));
		sha256_from_sql(stmt, 3, &ci->revocation_hash);
		ci->order = sqlite3_column_int64(stmt, 4);

		if (sqlite3_column_type(stmt, 5) == SQLITE_NULL)
			ci->sig = NULL;
		else {
			ci->sig = tal(ci, ecdsa_signature);
			sig_from_sql(stmt, 5, ci->sig);
		}

		/* Set once we have updated HTLCs. */
		ci->cstate = NULL;
		ci->tx = NULL;
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_commit_info:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));
	tal_free(ctx);

	if (!lnchn->local.commit)
		fatal("load_lnchn_commit_info:no local commit info found");
	if (!lnchn->remote.commit)
		fatal("load_lnchn_commit_info:no remote commit info found");
}

/* Because their HTLCs are not ordered wrt to ours, we can go negative
 * and do normally-impossible things in intermediate states.  So we
 * mangle cstate balances manually. */
static void apply_htlc(struct log *log, struct channel_state *cstate, const struct htlc *htlc,
		       enum side side)
{
	const char *sidestr = side_to_str(side);

	if (!htlc_has(htlc, HTLC_FLAG(side,HTLC_F_WAS_COMMITTED)))
		return;

	log_debug(log, "  %s committed", sidestr);
	force_add_htlc(cstate, htlc);

	if (!htlc_has(htlc, HTLC_FLAG(side, HTLC_F_COMMITTED))) {
		log_debug(log, "  %s %s",
			  sidestr, htlc->r ? "resolved" : "failed");
		if (htlc->r)
			force_fulfill_htlc(cstate, htlc);
		else
			force_fail_htlc(cstate, htlc);
	}
}

/* As we load the HTLCs, we apply them to get the final channel_state.
 * We also get the last used htlc id.
 * This is slow, but sure. */
static void load_lnchn_htlcs(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	const char *select;
	bool to_them_only, to_us_only;

	select = tal_fmt(ctx,
			 "SELECT * FROM htlcs WHERE lnchn = x'%s' ORDER BY id;",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_htlcs:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	lnchn->local.commit->cstate = initial_cstate(lnchn->local.commit,
						    lnchn->anchor.satoshis,
						    lnchn->local.commit_fee_rate,
						    lnchn->local.offer_anchor ?
						    LOCAL : REMOTE);
	lnchn->remote.commit->cstate = initial_cstate(lnchn->remote.commit,
						     lnchn->anchor.satoshis,
						     lnchn->remote.commit_fee_rate,
						     lnchn->local.offer_anchor ?
						     LOCAL : REMOTE);

	/* We rebuild cstate by running *every* HTLC through. */
	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		struct htlc *htlc;
		struct sha256 rhash;
		enum htlc_state hstate;

		if (err != SQLITE_ROW)
			fatal("load_lnchn_htlcs:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 11)
			fatal("load_lnchn_htlcs:step gave %i cols, not 11",
			      sqlite3_column_count(stmt));
		sha256_from_sql(stmt, 5, &rhash);

		hstate = htlc_state_from_name(sqlite3_column_str(stmt, 2));
		if (hstate == HTLC_STATE_INVALID)
			fatal("load_lnchn_htlcs:invalid state %s",
			      sqlite3_column_str(stmt, 2));
		htlc = lnchn_new_htlc(lnchn,
				     sqlite3_column_int64(stmt, 3),
				     &rhash,
				     sqlite3_column_int64(stmt, 4),
                     sqlite3_column_int64(stmt, 5),
				     hstate);

		if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
			htlc->r = tal(htlc, struct preimage);
			from_sql_blob(stmt, 6, htlc->r, sizeof(*htlc->r));
		}
		if (sqlite3_column_type(stmt, 8) != SQLITE_NULL) {
			htlc->fail = tal_sql_blob(htlc, stmt, 10);
		}

		if (htlc->r && htlc->fail)
			fatal("%s HTLC %s has failed and fulfilled?",
			      htlc_owner(htlc) == LOCAL ? "local" : "remote",
                  tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)));

		log_debug(lnchn->log, "Loaded %s HTLC %s (%s)",
			  htlc_owner(htlc) == LOCAL ? "local" : "remote",
              tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)), htlc_state_name(htlc->state));

		/* Update cstate with this HTLC. */
		apply_htlc(lnchn->log, lnchn->local.commit->cstate, htlc, LOCAL);
		apply_htlc(lnchn->log, lnchn->remote.commit->cstate, htlc, REMOTE);
	}

	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_htlcs:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	/* Now set any in-progress fee changes. */
	select = tal_fmt(ctx,
			 "SELECT * FROM feechanges WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_htlcs:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		enum feechange_state feechange_state;

		if (err != SQLITE_ROW)
			fatal("load_lnchn_htlcs:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 3)
			fatal("load_lnchn_htlcs:step gave %i cols, not 3",
			      sqlite3_column_count(stmt));

		feechange_state
			= feechange_state_from_name(sqlite3_column_str(stmt, 1));
		if (feechange_state == FEECHANGE_STATE_INVALID)
			fatal("load_lnchn_htlcs:invalid feechange state %s",
			      sqlite3_column_str(stmt, 1));
		if (lnchn->feechanges[feechange_state])
			fatal("load_lnchn_htlcs: second feechange in state %s",
			      sqlite3_column_str(stmt, 1));
		lnchn->feechanges[feechange_state]
			= new_feechange(lnchn, sqlite3_column_int64(stmt, 2),
					feechange_state);
	}
	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("load_lnchn_htlcs:finalize gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	if (!balance_after_force(lnchn->local.commit->cstate)
	    || !balance_after_force(lnchn->remote.commit->cstate))
		fatal("load_lnchn_htlcs:channel didn't balance");

	/* Update commit->tx and commit->map */
	lnchn->local.commit->tx = create_commit_tx(lnchn->local.commit,
						  lnchn,
						  &lnchn->local.commit->revocation_hash,
						  lnchn->local.commit->cstate,
						  LOCAL, &to_them_only);
	bitcoin_txid(lnchn->local.commit->tx, &lnchn->local.commit->txid);

	lnchn->remote.commit->tx = create_commit_tx(lnchn->remote.commit,
						   lnchn,
						   &lnchn->remote.commit->revocation_hash,
						   lnchn->remote.commit->cstate,
						   REMOTE, &to_us_only);
	bitcoin_txid(lnchn->remote.commit->tx, &lnchn->remote.commit->txid);

	lnchn->remote.staging_cstate = copy_cstate(lnchn, lnchn->remote.commit->cstate);
	lnchn->local.staging_cstate = copy_cstate(lnchn, lnchn->local.commit->cstate);
	log_debug(lnchn->log, "Local staging: pay %u/%u fee %u/%u htlcs %u/%u",
		  lnchn->local.staging_cstate->side[LOCAL].pay_msat,
		  lnchn->local.staging_cstate->side[REMOTE].pay_msat,
		  lnchn->local.staging_cstate->side[LOCAL].fee_msat,
		  lnchn->local.staging_cstate->side[REMOTE].fee_msat,
		  lnchn->local.staging_cstate->side[LOCAL].num_htlcs,
		  lnchn->local.staging_cstate->side[REMOTE].num_htlcs);
	log_debug(lnchn->log, "Remote staging: pay %u/%u fee %u/%u htlcs %u/%u",
		  lnchn->remote.staging_cstate->side[LOCAL].pay_msat,
		  lnchn->remote.staging_cstate->side[REMOTE].pay_msat,
		  lnchn->remote.staging_cstate->side[LOCAL].fee_msat,
		  lnchn->remote.staging_cstate->side[REMOTE].fee_msat,
		  lnchn->remote.staging_cstate->side[LOCAL].num_htlcs,
		  lnchn->remote.staging_cstate->side[REMOTE].num_htlcs);

	tal_free(ctx);
}

///* FIXME: A real database person would do this in a single clause along
// * with loading the htlcs in the first place! */
//static void connect_htlc_src(struct lightningd_state *dstate)
//{
//	sqlite3 *sql = dstate->db->sql;
//	int err;
//	sqlite3_stmt *stmt;
//	char *ctx = tal_tmpctx(dstate);
//	const char *select;
//
//	select = tal_fmt(ctx,
//			 "SELECT lnchn,id,state,src_lnchn,src_id FROM htlcs WHERE src_lnchn IS NOT NULL AND state <> 'RCVD_REMOVE_ACK_REVOCATION' AND state <> 'SENT_REMOVE_ACK_REVOCATION';");
//
//	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
//	if (err != SQLITE_OK)
//		fatal("connect_htlc_src:%s gave %s:%s",
//		      select, sqlite3_errstr(err), sqlite3_errmsg(sql));
//
//	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
//		struct pubkey id;
//		struct LNchannel *lnchn;
//		struct htlc *htlc;
//		enum htlc_state s;
//
//		if (err != SQLITE_ROW)
//			fatal("connect_htlc_src:step gave %s:%s",
//			      sqlite3_errstr(err), sqlite3_errmsg(sql));
//
//		pubkey_from_sql(stmt, 0, &id);
//		lnchn = find_lnchn(dstate, &id);
//		if (!lnchn)
//			continue;
//
//		s = htlc_state_from_name(sqlite3_column_str(stmt, 2));
//		if (s == HTLC_STATE_INVALID)
//			fatal("connect_htlc_src:unknown state %s",
//			      sqlite3_column_str(stmt, 2));
//
//		htlc = htlc_get(&lnchn->htlcs, sqlite3_column_int64(stmt, 1),
//				htlc_state_owner(s));
//		if (!htlc)
//			fatal("connect_htlc_src:unknown htlc %"PRIuSQLITE64" state %s",
//			      sqlite3_column_int64(stmt, 1),
//			      sqlite3_column_str(stmt, 2));
//
//		pubkey_from_sql(stmt, 4, &id);
//		lnchn = find_lnchn(dstate, &id);
//		if (!lnchn)
//			fatal("connect_htlc_src:unknown src lnchn %s",
//			      tal_hexstr(dstate, &id, sizeof(id)));
//
//		/* Source must be a HTLC they offered. */
//		htlc->src = htlc_get(&lnchn->htlcs,
//				     sqlite3_column_int64(stmt, 4),
//				     REMOTE);
//		if (!htlc->src)
//			fatal("connect_htlc_src:unknown src htlc");
//	}
//
//	err = sqlite3_finalize(stmt);
//	if (err != SQLITE_OK)
//		fatal("load_lnchn_htlcs:finalize gave %s:%s",
//		      sqlite3_errstr(err),
//		      sqlite3_errmsg(dstate->db->sql));
//	tal_free(ctx);
//}

static const char *linearize_shachain(const tal_t *ctx,
				      const struct shachain *shachain)
{
	size_t i;
	u8 *p = tal_arr(ctx, u8, 0);
	const char *str;

	push_le64(shachain->min_index, push, &p);
	push_le32(shachain->num_valid, push, &p);
	for (i = 0; i < shachain->num_valid; i++) {
		push_le64(shachain->known[i].index, push, &p);
		push(&shachain->known[i].hash, sizeof(shachain->known[i].hash),
		     &p);
	}
	for (i = shachain->num_valid; i < ARRAY_SIZE(shachain->known); i++) {
		static u8 zeroes[sizeof(shachain->known[0].hash)];
		push_le64(0, push, &p);
		push(zeroes, sizeof(zeroes), &p);
	}

	assert(tal_count(p) == SHACHAIN_SIZE);
	str = tal_hex(ctx, p);
	tal_free(p);
	return str;
}

static bool delinearize_shachain(struct shachain *shachain,
				 const void *data, size_t len)
{
	size_t i;
	const u8 *p = data;

	shachain->min_index = pull_le64(&p, &len);
	shachain->num_valid = pull_le32(&p, &len);
	for (i = 0; i < ARRAY_SIZE(shachain->known); i++) {
		shachain->known[i].index = pull_le64(&p, &len);
		pull(&p, &len, &shachain->known[i].hash,
		     sizeof(shachain->known[i].hash));
	}
	return p && len == 0;
}

static void load_lnchn_shachain(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	bool shachain_found = false;
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT * FROM shachain WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_shachain:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		const char *hexstr;

		if (err != SQLITE_ROW)
			fatal("load_lnchn_shachain:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		/* shachain (lnchn "SQL_PUBKEY", shachain BINARY(%zu) */
		if (sqlite3_column_count(stmt) != 2)
			fatal("load_lnchn_shachain:step gave %i cols, not 2",
			      sqlite3_column_count(stmt));

		if (shachain_found)
			fatal("load_lnchn_shachain:multiple shachains?");

		hexstr = tal_hexstr(ctx, sqlite3_column_blob(stmt, 1),
				    sqlite3_column_bytes(stmt, 1));
		if (!delinearize_shachain(&lnchn->their_preimages,
					  sqlite3_column_blob(stmt, 1),
					  sqlite3_column_bytes(stmt, 1)))
			fatal("load_lnchn_shachain:invalid shachain %s",
			      hexstr);
		shachain_found = true;
	}

	if (!shachain_found)
		fatal("load_lnchn_shachain:no shachain");
	tal_free(ctx);
}

/* We may not have one, and that's OK. */
static void load_lnchn_closing(struct LNchannel *lnchn)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = lnchn->dstate->db->sql;
	char *ctx = tal_tmpctx(lnchn);
	bool closing_found = false;
	const char *select;

	select = tal_fmt(ctx,
			 "SELECT * FROM closing WHERE lnchn = x'%s';",
			 pubkey_to_hexstr(ctx, lnchn->id));

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("load_lnchn_closing:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		if (err != SQLITE_ROW)
			fatal("load_lnchn_closing:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));

		if (sqlite3_column_count(stmt) != 9)
			fatal("load_lnchn_closing:step gave %i cols, not 9",
			      sqlite3_column_count(stmt));

		if (closing_found)
			fatal("load_lnchn_closing:multiple closing?");

		lnchn->closing.our_fee = sqlite3_column_int64(stmt, 1);
		lnchn->closing.their_fee = sqlite3_column_int64(stmt, 2);
		if (sqlite3_column_type(stmt, 3) == SQLITE_NULL)
			lnchn->closing.their_sig = NULL;
		else {
			lnchn->closing.their_sig = tal(lnchn,
						      ecdsa_signature);
			sig_from_sql(stmt, 3, lnchn->closing.their_sig);
		}
		lnchn->closing.our_script = tal_sql_blob(lnchn, stmt, 4);
		lnchn->closing.their_script = tal_sql_blob(lnchn, stmt, 5);
		lnchn->closing.shutdown_order = sqlite3_column_int64(stmt, 6);
		lnchn->closing.closing_order = sqlite3_column_int64(stmt, 7);
		lnchn->closing.sigs_in = sqlite3_column_int64(stmt, 8);
		closing_found = true;
	}
	tal_free(ctx);
}

/* FIXME: much of this is redundant. */
static void restore_lnchn_local_visible_state(struct LNchannel *lnchn)
{
	assert(lnchn->local.offer_anchor == !lnchn->remote.offer_anchor);

	/* lnchn->local.commitkey and lnchn->local.finalkey set by
	 * lnchn_set_secrets_from_db(). */
	memcheck(&lnchn->local.commitkey, sizeof(lnchn->local.commitkey));
	memcheck(&lnchn->local.finalkey, sizeof(lnchn->local.finalkey));
	/* These set in new_lnchn */
	memcheck(&lnchn->local.locktime, sizeof(lnchn->local.locktime));
	memcheck(&lnchn->local.mindepth, sizeof(lnchn->local.mindepth));
	/* This set in db_load_lnchns */
	memcheck(&lnchn->local.commit_fee_rate,
		 sizeof(lnchn->local.commit_fee_rate));

	lnchn_get_revocation_hash(lnchn,
				 lnchn->local.commit->commit_num + 1,
				 &lnchn->local.next_revocation_hash);

	//if (state_is_normal(lnchn->state))
	//	lnchn->nc = add_connection(lnchn->dstate->rstate,
	//				  &lnchn->dstate->id, lnchn->id,
	//				  lnchn->dstate->config.fee_base,
	//				  lnchn->dstate->config.fee_per_satoshi,
	//				  lnchn->dstate->config.min_htlc_expiry,
	//				  lnchn->dstate->config.min_htlc_expiry);

	lnchn->their_commitsigs = lnchn->local.commit->commit_num + 1;
	/* If they created anchor, they didn't send a sig for first commit */
	if (!lnchn->anchor.ours)
		lnchn->their_commitsigs--;

	if (lnchn->local.commit->order + 1 > lnchn->order_counter)
		lnchn->order_counter = lnchn->local.commit->order + 1;
	if (lnchn->remote.commit->order + 1 > lnchn->order_counter)
		lnchn->order_counter = lnchn->remote.commit->order + 1;
	if (lnchn->closing.closing_order + 1 > lnchn->order_counter)
		lnchn->order_counter = lnchn->closing.closing_order + 1;
	if (lnchn->closing.shutdown_order + 1 > lnchn->order_counter)
		lnchn->order_counter = lnchn->closing.shutdown_order + 1;
}

static void db_load_lnchns(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;
	struct LNchannel *lnchn;
    struct htlc_map_iter it;
    struct htlc *h;

	err = sqlite3_prepare_v2(dstate->db->sql, "SELECT * FROM lnchns;", -1,
				 &stmt, NULL);

	if (err != SQLITE_OK)
		fatal("db_load_lnchns:prepare gave %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(dstate->db->sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		enum state state;
		struct log *l;
		struct pubkey id;
		const char *idstr;

		if (err != SQLITE_ROW)
			fatal("db_load_lnchns:step gave %s:%s",
			      sqlite3_errstr(err),
			      sqlite3_errmsg(dstate->db->sql));
		if (sqlite3_column_count(stmt) != 4)
			fatal("db_load_lnchns:step gave %i cols, not 4",
			      sqlite3_column_count(stmt));
		state = name_to_state(sqlite3_column_str(stmt, 1));
		if (state == STATE_MAX)
			fatal("db_load_lnchns:unknown state %s",
			      sqlite3_column_str(stmt, 1));
		pubkey_from_sql(stmt, 0, &id);
		idstr = pubkey_to_hexstr(dstate, &id);
		l = new_log(dstate, dstate->log_book, "%s:", idstr);
		tal_free(idstr);
		lnchn = new_LNChannel(dstate, l);
        lnchn->state = state;
        lnchn->state_height = sqlite3_column_int64(stmt, 5);
        lnchn->local.offer_anchor = sqlite3_column_int(stmt, 2);
		lnchn->id = tal_dup(lnchn, struct pubkey, &id);
		lnchn->local.commit_fee_rate = sqlite3_column_int64(stmt, 3);
        address_from_sql(stmt, 4, &lnchn->redeem_addr);
		lnchn->order_counter = 1;
		log_debug(lnchn->log, "%s:%s",
			  __func__, state_name(lnchn->state));

		load_lnchn_secrets(lnchn);
		load_lnchn_closing(lnchn);
		lnchn->anchor.min_depth = 0;
		if (lnchn->state >= STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE
		    && !state_is_error(lnchn->state)) {
			load_lnchn_anchor(lnchn);
			load_lnchn_visible_state(lnchn);
			load_lnchn_shachain(lnchn);
			load_lnchn_commit_info(lnchn);
			load_lnchn_htlcs(lnchn);
			restore_lnchn_local_visible_state(lnchn);
		}
		if (lnchn->local.offer_anchor)
			load_lnchn_anchor_input(lnchn);

        lite_reg_channel(dstate->channels, lnchn);

        for (h = htlc_map_first(&lnchn->htlcs, &it);
            h;
            h = htlc_map_next(&lnchn->htlcs, &it)) {
            lite_reg_htlc(dstate->channels, lnchn, h);
        }        
	}
	err = sqlite3_finalize(stmt);
	if (err != SQLITE_OK)
		fatal("db_load_lnchns:finalize gave %s:%s",
		      sqlite3_errstr(err),
		      sqlite3_errmsg(dstate->db->sql));

//	connect_htlc_src(dstate);
}


//static const char *pubkeys_to_hex(const tal_t *ctx, const struct pubkey *ids)
//{
//	u8 *ders = tal_arr(ctx, u8, PUBKEY_DER_LEN * tal_count(ids));
//	size_t i;
//
//	for (i = 0; i < tal_count(ids); i++)
//		pubkey_to_der(ders + i * PUBKEY_DER_LEN, &ids[i]);
//
//	return tal_hex(ctx, ders);
//}
//static struct pubkey *pubkeys_from_arr(const tal_t *ctx,
//				       const void *blob, size_t len)
//{
//	struct pubkey *ids;
//	size_t i;
//
//	if (len % PUBKEY_DER_LEN)
//		fatal("ids array bad length %zu", len);
//
//	ids = tal_arr(ctx, struct pubkey, len / PUBKEY_DER_LEN);
//	for (i = 0; i < tal_count(ids); i++) {
//		if (!pubkey_from_der(blob, PUBKEY_DER_LEN, &ids[i]))
//			fatal("ids array invalid %zu", i);
//		blob = (const u8 *)blob + PUBKEY_DER_LEN;
//	}
//	return ids;
//}


static void db_check_version(struct lightningd_state *dstate)
{
	int err;
	sqlite3_stmt *stmt;
	sqlite3 *sql = dstate->db->sql;
	char *ctx = tal_tmpctx(dstate);
	const char *select;

	select = tal_fmt(ctx, "SELECT * FROM version;");

	err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
	if (err != SQLITE_OK)
		fatal("DATABASE NEEDS UPDATE.  Can't access VERSION: %s:%s",
		      sqlite3_errstr(err), sqlite3_errmsg(sql));

	while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
		const char *ver;

		if (err != SQLITE_ROW)
			fatal("db_check_version:step gave %s:%s",
			      sqlite3_errstr(err), sqlite3_errmsg(sql));
		ver = sqlite3_column_str(stmt, 0);
		if (!streq(ver, VERSION)) {
			if (dstate->config.db_version_ignore)
				log_unusual(dstate->base_log,
					    "DATABASE NEEDS UPDATE."
					    " Version %s does not match %s",
					    ver, VERSION);
			else
				fatal("DATABASE NEEDS UPDATE."
				      " Version %s does not match %s",
				      ver, VERSION);
		}
	}
	tal_free(ctx);
}

static void db_load(struct lightningd_state *dstate)
{
	db_check_version(dstate);
//	db_load_wallet(dstate);
//	db_load_addresses(dstate);
	db_load_lnchns(dstate);
//	db_load_pay(dstate);
//	db_load_invoice(dstate);
}

void db_init(struct lightningd_state *dstate)
{
	int err;
	bool created = false;

	if (SQLITE_VERSION_NUMBER != sqlite3_libversion_number())
		fatal("SQLITE version mistmatch: compiled %u, now %u",
		      SQLITE_VERSION_NUMBER, sqlite3_libversion_number());

	dstate->db = tal(dstate, struct db);

	err = sqlite3_open_v2(DB_FILE, &dstate->db->sql,
			      SQLITE_OPEN_READWRITE, NULL);
	if (err != SQLITE_OK) {
		log_unusual(dstate->base_log,
			    "Error opening %s (%s), trying to create",
			    DB_FILE, sqlite3_errstr(err));
		err = sqlite3_open_v2(DB_FILE, &dstate->db->sql,
				      SQLITE_OPEN_READWRITE
				      | SQLITE_OPEN_CREATE, NULL);
		if (err != SQLITE_OK)
			fatal("failed creating %s: %s",
			      DB_FILE, sqlite3_errstr(err));
		created = true;
	}

	tal_add_destructor(dstate->db, close_db);
	dstate->db->in_transaction = false;
	dstate->db->err = NULL;

	if (!created) {
		db_load(dstate);
		return;
	}

	/* Set up tables. */
	dstate->db->in_transaction = true;
	db_exec(__func__, dstate, "BEGIN IMMEDIATE;");
	db_exec(__func__, dstate,
		//TABLE(wallet,
		//      SQL_PRIVKEY(privkey))
		//TABLE(pay,
		//      SQL_RHASH(rhash), SQL_U64(msatoshi),
		//      SQL_BLOB(ids), SQL_PUBKEY(htlc_lnchn),
		//      SQL_U64(htlc_id), SQL_R(r), SQL_FAIL(fail),
		//      "PRIMARY KEY(rhash)")
		//TABLE(invoice,
		//      SQL_R(r), SQL_U64(msatoshi), SQL_INVLABEL(label),
		//      SQL_U64(paid_num),
		//      "PRIMARY KEY(label)")
		TABLE(anchor_inputs,
		      SQL_PUBKEY(lnchn),
		      SQL_TXID(txid), SQL_U32(idx),
		      SQL_U64(in_amount), SQL_U64(out_amount),
		      SQL_PUBKEY(walletkey))
		TABLE(anchors,
		      SQL_PUBKEY(lnchn),
		      SQL_TXID(txid), SQL_U32(idx), SQL_U64(amount),
		      SQL_U32(ok_depth), SQL_U32(min_depth),
		      SQL_BOOL(ours))
		/* FIXME: state in key is overkill: just need side */
		TABLE(htlcs,
		      SQL_PUBKEY(lnchn), SQL_U64(id) /* we keep this dummy item to avoid changing too much codes*/,
		      SQL_STATENAME(state), SQL_U64(msatoshi),
		      SQL_U32(expiry), SQL_RHASH(rhash), SQL_R(r),
		      SQL_U32(src_expiry), SQL_BLOB(fail),/*SQL_PUBKEY(src_lnchn),
		      SQL_U64(src_id), SQL_BLOB(fail),*/
		      "PRIMARY KEY(lnchn, rhash)")
		TABLE(feechanges,
		      SQL_PUBKEY(lnchn), SQL_STATENAME(state),
		      SQL_U32(fee_rate),
		      "PRIMARY KEY(lnchn,state)")
		TABLE(commit_info,
		      SQL_PUBKEY(lnchn), SQL_U32(side),
		      SQL_U64(commit_num), SQL_SHA256(revocation_hash),
		      SQL_U64(xmit_order), SQL_SIGNATURE(sig),
		      SQL_SHA256(prev_revocation_hash),
		      "PRIMARY KEY(lnchn, side)")
		TABLE(shachain,
		      SQL_PUBKEY(lnchn), SQL_SHACHAIN(shachain),
		      "PRIMARY KEY(lnchn)")
		TABLE(their_visible_state,
		      SQL_PUBKEY(lnchn), SQL_BOOL(offered_anchor),
		      SQL_PUBKEY(commitkey), SQL_PUBKEY(finalkey),
		      SQL_U32(locktime), SQL_U32(mindepth),
		      SQL_U32(commit_fee_rate),
		      SQL_SHA256(next_revocation_hash),
		      "PRIMARY KEY(lnchn)")
		TABLE(their_commitments,
		      SQL_PUBKEY(lnchn), SQL_SHA256(txid),
		      SQL_U64(commit_num),
		      "PRIMARY KEY(lnchn, txid)")
		TABLE(lnchn_secrets,
		      SQL_PUBKEY(lnchn), SQL_PRIVKEY(commitkey),
		      SQL_PRIVKEY(finalkey),
		      SQL_SHA256(revocation_seed),
		      "PRIMARY KEY(lnchn)")
		//TABLE(lnchn_address,
		//      SQL_PUBKEY(lnchn), SQL_BLOB(addr),
		//      "PRIMARY KEY(lnchn)")
		TABLE(closing,
		      SQL_PUBKEY(lnchn), SQL_U64(our_fee),
		      SQL_U64(their_fee), SQL_SIGNATURE(their_sig),
		      SQL_BLOB(our_script), SQL_BLOB(their_script),
		      SQL_U64(shutdown_order), SQL_U64(closing_order),
		      SQL_U64(sigs_in),
		      "PRIMARY KEY(lnchn)")
		TABLE(lnchns,
		      SQL_PUBKEY(lnchn), SQL_STATENAME(state),
		      SQL_BOOL(offered_anchor), SQL_U32(our_feerate),
              SQL_BLOB(redeemaddr), SQL_U32(state_height),
		      "PRIMARY KEY(lnchn)")
		TABLE(version, "version VARCHAR(100)"));
	db_exec(__func__, dstate, "INSERT INTO version VALUES ('"VERSION"');");
	db_exec(__func__, dstate, "COMMIT;");
	dstate->db->in_transaction = false;

	if (dstate->db->err) {
		unlink(DB_FILE);
		fatal("%s", dstate->db->err);
	}
}

void db_set_anchor(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid;

	assert(lnchn->dstate->db->in_transaction);
	lnchnid = pubkey_to_hexstr(ctx, lnchn->id);
	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO anchors VALUES (x'%s', x'%s', %u, %"PRIu64", %i, %u, %s);",
		lnchnid,
		tal_hexstr(ctx, &lnchn->anchor.txid, sizeof(lnchn->anchor.txid)),
		lnchn->anchor.index,
		lnchn->anchor.satoshis,
		lnchn->anchor.ok_depth,
		lnchn->anchor.min_depth,
		sql_bool(lnchn->anchor.ours));

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO commit_info VALUES(x'%s', '%s', 0, x'%s', %"PRIi64", %s, NULL);",
		lnchnid,
		side_to_str(LOCAL),
		tal_hexstr(ctx, &lnchn->local.commit->revocation_hash,
			   sizeof(lnchn->local.commit->revocation_hash)),
		lnchn->local.commit->order,
		sig_to_sql(ctx, lnchn->local.commit->sig));

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO commit_info VALUES(x'%s', '%s', 0, x'%s', %"PRIi64", %s, NULL);",
		lnchnid,
		side_to_str(REMOTE),
		tal_hexstr(ctx, &lnchn->remote.commit->revocation_hash,
			   sizeof(lnchn->remote.commit->revocation_hash)),
		lnchn->remote.commit->order,
		sig_to_sql(ctx, lnchn->remote.commit->sig));

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO shachain VALUES (x'%s', x'%s');",
		lnchnid,
		linearize_shachain(ctx, &lnchn->their_preimages));

	tal_free(ctx);
}

void db_set_visible_state(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO their_visible_state VALUES (x'%s', %s, x'%s', x'%s', %u, %u, %"PRIu64", x'%s');",
		lnchnid,
		sql_bool(lnchn->remote.offer_anchor),
		pubkey_to_hexstr(ctx, &lnchn->remote.commitkey),
		pubkey_to_hexstr(ctx, &lnchn->remote.finalkey),
		lnchn->remote.locktime.locktime,
		lnchn->remote.mindepth,
		lnchn->remote.commit_fee_rate,
		tal_hexstr(ctx, &lnchn->remote.next_revocation_hash,
			   sizeof(lnchn->remote.next_revocation_hash)));

	tal_free(ctx);
}

void db_update_next_revocation_hash(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s):%s", __func__, lnchnid,
		tal_hexstr(ctx, &lnchn->remote.next_revocation_hash,
			   sizeof(lnchn->remote.next_revocation_hash)));
	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE their_visible_state SET next_revocation_hash=x'%s' WHERE lnchn=x'%s';",
		tal_hexstr(ctx, &lnchn->remote.next_revocation_hash,
			   sizeof(lnchn->remote.next_revocation_hash)),
		lnchnid);
	tal_free(ctx);
}

void db_create_lnchn(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);

    db_exec(__func__, lnchn->dstate,
        "INSERT INTO lnchns VALUES (x'%s', '%s', %s, %"PRIi64", x'%s', %u);",
        lnchnid,
        state_name(lnchn->state),
        sql_bool(lnchn->local.offer_anchor),
        lnchn->local.commit_fee_rate,
        tal_hexstr(ctx, &lnchn->redeem_addr, sizeof(lnchn->redeem_addr.addr)),
        lnchn->state_height);

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO lnchn_secrets VALUES (x'%s', %s);",
		lnchnid, lnchn_secrets_for_db(ctx, lnchn));

	if (lnchn->local.offer_anchor)
		db_exec(__func__, lnchn->dstate,
			"INSERT INTO anchor_inputs VALUES"
			" (x'%s', x'%s', %u, %"PRIi64", %"PRIi64", x'%s');",
			lnchnid,
			tal_hexstr(ctx, &lnchn->anchor.input->txid,
				   sizeof(lnchn->anchor.input->txid)),
			lnchn->anchor.input->index,
			lnchn->anchor.input->in_amount,
			lnchn->anchor.input->out_amount,
			pubkey_to_hexstr(ctx, &lnchn->anchor.input->walletkey));



	tal_free(ctx);
}

void db_start_transaction(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(!lnchn->dstate->db->in_transaction);
	lnchn->dstate->db->in_transaction = true;
	lnchn->dstate->db->err = tal_free(lnchn->dstate->db->err);

	db_exec(__func__, lnchn->dstate, "BEGIN IMMEDIATE;");
	tal_free(ctx);
}

void db_abort_transaction(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);
	lnchn->dstate->db->in_transaction = false;
	db_exec(__func__, lnchn->dstate, "ROLLBACK;");
	tal_free(ctx);
}

const char *db_commit_transaction(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);
	if (!db_exec(__func__, lnchn->dstate, "COMMIT;"))
		db_abort_transaction(lnchn);
	else
		lnchn->dstate->db->in_transaction = false;
	tal_free(ctx);

	return lnchn->dstate->db->err;
}

void db_new_htlc(struct LNchannel *lnchn, const struct htlc *htlc)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO htlcs VALUES"
		" (x'%s', %"PRIu64", '%s', %"PRIu64", %u, x'%s', NULL, %u, NULL);",
		lnchnid,
		0,
		htlc_state_name(htlc->state),
		htlc->msatoshi,
		abs_locktime_to_blocks(&htlc->expiry),
		tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)),
        htlc->src_expiry ? abs_locktime_to_blocks(htlc->src_expiry) : 0);

	tal_free(ctx);
}

void db_new_feechange(struct LNchannel *lnchn, const struct feechange *feechange)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);

	db_exec(__func__, lnchn->dstate,
		"INSERT INTO feechanges VALUES"
		" (x'%s', '%s', %"PRIu64");",
		lnchnid,
		feechange_state_name(feechange->state),
		feechange->fee_rate);

	tal_free(ctx);
}

void db_update_htlc_state(struct LNchannel *lnchn, const struct htlc *htlc,
			  enum htlc_state oldstate)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s): %s %s->%s", __func__, lnchnid,
          tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)), htlc_state_name(oldstate),
		  htlc_state_name(htlc->state));
	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE htlcs SET state='%s' WHERE lnchn=x'%s' AND rhash=x'%s';",
		htlc_state_name(htlc->state), lnchnid,
        tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)));

	tal_free(ctx);
}

void db_update_feechange_state(struct LNchannel *lnchn,
			       const struct feechange *f,
			       enum feechange_state oldstate)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s): %s->%s", __func__, lnchnid,
		  feechange_state_name(oldstate),
		  feechange_state_name(f->state));
	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE feechanges SET state='%s' WHERE lnchn=x'%s' AND state='%s';",
		feechange_state_name(f->state), lnchnid,
		feechange_state_name(oldstate));

	tal_free(ctx);
}

void db_remove_feechange(struct LNchannel *lnchn, const struct feechange *feechange,
			 enum feechange_state oldstate)
{
	const char *ctx = tal(lnchn, char);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);
	assert(lnchn->dstate->db->in_transaction);

	db_exec(__func__, lnchn->dstate,
		"DELETE FROM feechanges WHERE lnchn=x'%s' AND state='%s';",
		lnchnid, feechange_state_name(oldstate));

	tal_free(ctx);
}

void db_update_state(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE lnchns SET state='%s' AND state_height=%u WHERE lnchn=x'%s';",
		state_name(lnchn->state), lnchn->state_height, lnchnid);
	tal_free(ctx);
}

void db_htlc_fulfilled(struct LNchannel *lnchn, const struct htlc *htlc)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE htlcs SET r=x'%s' WHERE lnchn=x'%s' AND rhash=x'%s';",
		tal_hexstr(ctx, htlc->r, sizeof(*htlc->r)),
		lnchnid,
        tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)));

	tal_free(ctx);
}

void db_htlc_failed(struct LNchannel *lnchn, const struct htlc *htlc)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE htlcs SET fail=x'%s' WHERE lnchn=x'%s' AND rhash=x'%s';",
		tal_hexstr(ctx, htlc->fail, sizeof(*htlc->fail)),
		lnchnid,
        tal_hexstr(ctx, &htlc->rhash, sizeof(htlc->rhash)));

	tal_free(ctx);
}

void db_new_commit_info(struct LNchannel *lnchn, enum side side,
			const struct sha256 *prev_rhash)
{
	struct commit_info *ci;
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	if (side == LOCAL) {
		ci = lnchn->local.commit;
	} else {
		ci = lnchn->remote.commit;
	}

	db_exec(__func__, lnchn->dstate, "UPDATE commit_info SET commit_num=%"PRIu64", revocation_hash=x'%s', sig=%s, xmit_order=%"PRIi64", prev_revocation_hash=%s WHERE lnchn=x'%s' AND side='%s';",
		ci->commit_num,
		tal_hexstr(ctx, &ci->revocation_hash,
			   sizeof(ci->revocation_hash)),
		sig_to_sql(ctx, ci->sig),
		ci->order,
		sql_hex_or_null(ctx, prev_rhash, sizeof(*prev_rhash)),
		lnchnid, side_to_str(side));
	tal_free(ctx);
}

/* FIXME: Is this strictly necessary? */
void db_remove_their_prev_revocation_hash(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);

	db_exec(__func__, lnchn->dstate, "UPDATE commit_info SET prev_revocation_hash=NULL WHERE lnchn=x'%s' AND side='REMOTE' and prev_revocation_hash IS NOT NULL;",
			 lnchnid);
	tal_free(ctx);
}


void db_save_shachain(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate, "UPDATE shachain SET shachain=x'%s' WHERE lnchn=x'%s';",
		linearize_shachain(ctx, &lnchn->their_preimages),
		lnchnid);
	tal_free(ctx);
}

void db_add_commit_map(struct LNchannel *lnchn,
		       const struct sha256_double *txid, u64 commit_num)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s),commit_num=%"PRIu64, __func__, lnchnid,
		  commit_num);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"INSERT INTO their_commitments VALUES (x'%s', x'%s', %"PRIu64");",
		lnchnid,
		tal_hexstr(ctx, txid, sizeof(*txid)),
		commit_num);
	tal_free(ctx);
}

bool db_find_commit(struct LNchannel *lnchn,
    const struct sha256_double *txid, u64 *commit_num) {

    int err;
    sqlite3_stmt *stmt;
    sqlite3 *sql = lnchn->dstate->db->sql;
    char *ctx = tal_tmpctx(lnchn);
    const char *select;

    select = tal_fmt(ctx,
        "SELECT * FROM their_commitments WHERE lnchn=x'%s' AND txid=x'%s';",
        pubkey_to_hexstr(ctx, lnchn->id),
        tal_hexstr(ctx, txid, sizeof(*txid)));

    err = sqlite3_prepare_v2(sql, select, -1, &stmt, NULL);
    
    if (err != SQLITE_OK)
    	fatal("db_find_commit:prepare gave %s:%s",
    		    sqlite3_errstr(err), sqlite3_errmsg(sql));
    
    while ((err = sqlite3_step(stmt)) != SQLITE_DONE) {
    	if (err != SQLITE_ROW)
    		fatal("db_find_commit:step gave %s:%s",
    			    sqlite3_errstr(err),
    			    sqlite3_errmsg(sql));
    	if (sqlite3_column_count(stmt) != 1)
    		fatal("db_find_commit:step gave %i cols, not 3",
    			    sqlite3_column_count(stmt));
        *commit_num = sqlite3_column_int64(stmt, 2);
        return true;
    }

    return false;
}

///* FIXME: Clean out old ones! */
//bool db_add_lnchn_address(struct lightningd_state *dstate,
//			 const struct LNchannel_address *addr)
//{
//	const tal_t *ctx = tal_tmpctx(dstate);
//	bool ok;
//
//	log_debug(dstate->base_log, "%s", __func__);
//
//	assert(!dstate->db->in_transaction);
//	ok = db_exec(__func__, dstate,
//		     "INSERT OR REPLACE INTO lnchn_address VALUES (x'%s', x'%s');",
//		     pubkey_to_hexstr(ctx, &addr->id),
//		     netaddr_to_hex(ctx, &addr->addr));
//
//	tal_free(ctx);
//	return ok;
//}

void db_forget_lnchn(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);
	size_t i;
	const char *const tables[] = { "anchors", "htlcs", "commit_info", "shachain", "their_visible_state", "their_commitments", "lnchn_secrets", "closing", "lnchns" };
	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->state == STATE_CLOSED);

	db_start_transaction(lnchn);

	for (i = 0; i < ARRAY_SIZE(tables); i++) {
		db_exec(__func__, lnchn->dstate,
			"DELETE from %s WHERE lnchn=x'%s';",
			tables[i], lnchnid);
	}
	if (db_commit_transaction(lnchn) != NULL)
		fatal("%s:db_commi_transaction failed", __func__);

	tal_free(ctx);
}

void db_begin_shutdown(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"INSERT INTO closing VALUES (x'%s', 0, 0, NULL, NULL, NULL, 0, 0, 0);",
		lnchnid);
	tal_free(ctx);
}

void db_set_our_closing_script(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate, "UPDATE closing SET our_script=x'%s',shutdown_order=%"PRIu64" WHERE lnchn=x'%s';",
		tal_hex(ctx, lnchn->closing.our_script),
		lnchn->closing.shutdown_order,
		lnchnid);
	tal_free(ctx);
}

void db_set_their_closing_script(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(lnchn->dstate->db->in_transaction);
	db_exec(__func__, lnchn->dstate,
		"UPDATE closing SET their_script=x'%s' WHERE lnchn=x'%s';",
		tal_hex(ctx, lnchn->closing.their_script),
		lnchnid);
	tal_free(ctx);
}

/* For first time, we are in transaction to make it atomic with lnchn->state
 * update.  Later calls are not. */
/* FIXME: make caller wrap in transaction. */
void db_update_our_closing(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	db_exec(__func__, lnchn->dstate,
		"UPDATE closing SET our_fee=%"PRIu64", closing_order=%"PRIi64" WHERE lnchn=x'%s';",
		lnchn->closing.our_fee,
		lnchn->closing.closing_order,
		lnchnid);
	tal_free(ctx);
}

bool db_update_their_closing(struct LNchannel *lnchn)
{
	const char *ctx = tal_tmpctx(lnchn);
	bool ok;
	const char *lnchnid = pubkey_to_hexstr(ctx, lnchn->id);

	log_debug(lnchn->log, "%s(%s)", __func__, lnchnid);

	assert(!lnchn->dstate->db->in_transaction);
	ok = db_exec(__func__, lnchn->dstate,
		     "UPDATE closing SET their_fee=%"PRIu64", their_sig=%s, sigs_in=%u WHERE lnchn=x'%s';",
		     lnchn->closing.their_fee,
		     sig_to_sql(ctx, lnchn->closing.their_sig),
		     lnchn->closing.sigs_in,
		     lnchnid);
	tal_free(ctx);
	return ok;
}

