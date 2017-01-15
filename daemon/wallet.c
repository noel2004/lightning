/* Poor man's wallet.
 *  Needed because bitcoind doesn't (yet) produce segwit outputs, and we need
 *  such outputs for our anchor tx to make it immalleable.
 */
#include "bitcoin/base58.h"
#include "bitcoin/privkey.h"
#include "bitcoin/script.h"
#include "bitcoin/signature.h"
#include "bitcoin/tx.h"
#include "bitcoin/address.h"
#include "db.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "channel.h"
#include "chaintopology.h"
#include "log.h"
#include "wallet.h"
#include <inttypes.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <sodium/randombytes.h>

struct wallet {
	struct list_node list;
	struct privkey privkey;
	struct pubkey pubkey;
	struct ripemd160 p2sh;
};

bool restore_wallet_address(struct lightningd_state *dstate,
			    const struct privkey *privkey)
{
	struct wallet *w = tal(dstate, struct wallet);
	u8 *redeemscript;
	struct sha256 h;

	w->privkey = *privkey;
	if (!pubkey_from_privkey(&w->privkey, &w->pubkey))
		return false;

	redeemscript = bitcoin_redeem_p2wpkh(w, &w->pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&w->p2sh, h.u.u8, sizeof(h));

	list_add_tail(&dstate->wallet, &w->list);
	tal_free(redeemscript);
	return true;
}

static void new_keypair(struct privkey *privkey, struct pubkey *pubkey)
{
	do {
		randombytes_buf(privkey->secret, sizeof(privkey->secret));
	} while (!pubkey_from_privkey(privkey, pubkey));
}

static struct wallet *find_by_pubkey(struct lightningd_state *dstate,
				     const struct pubkey *walletkey)
{
	struct wallet *w;

	list_for_each(&dstate->wallet, w, list) {
		if (pubkey_eq(walletkey, &w->pubkey))
			return w;
	}
	return NULL;
}

bool wallet_add_signed_input(struct lightningd_state *dstate,
                const struct pubkey *walletkey,
                struct bitcoin_tx *tx,
                unsigned int input_num)
{
	u8 *redeemscript;
	struct bitcoin_signature sig;
	struct wallet *w = find_by_pubkey(dstate, walletkey);

	assert(input_num < tx->input_count);
	if (!w)
		return false;

	redeemscript = bitcoin_redeem_p2wpkh(tx, &w->pubkey);

	sig.stype = SIGHASH_ALL;
	sign_tx_input(tx, input_num,
		      redeemscript, tal_count(redeemscript),
		      p2wpkh_scriptcode(redeemscript, &w->pubkey),
		      &w->privkey,
		      &w->pubkey,
		      &sig.sig);

	bitcoin_witness_p2sh_p2wpkh(tx->input,
				    &tx->input[input_num],
				    &sig,
				    &w->pubkey);
	tal_free(redeemscript);
	return true;
}

bool wallet_can_spend(struct lightningd_state *dstate,
		      const struct bitcoin_tx_output *output,
		      struct pubkey *walletkey)
{
	struct ripemd160 h;
	struct wallet *w;

	if (!is_p2sh(output->script, output->script_length))
		return NULL;

	memcpy(&h, output->script + 2, 20);
	list_for_each(&dstate->wallet, w, list) {
		if (structeq(&h, &w->p2sh)) {
			*walletkey = w->pubkey;
			return true;
		}
	}
	return false;
}

static void json_newaddr(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct wallet *w = tal(cmd->dstate, struct wallet);
	u8 *redeemscript;
	struct sha256 h;

	new_keypair(&w->privkey, &w->pubkey);
	redeemscript = bitcoin_redeem_p2wpkh(cmd, &w->pubkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&w->p2sh, h.u.u8, sizeof(h));

	list_add_tail(&cmd->dstate->wallet, &w->list);
	db_add_wallet_privkey(cmd->dstate, &w->privkey);

	json_object_start(response, NULL);
	json_add_string(response, "address",
			p2sh_to_base58(cmd, cmd->dstate->testnet, &w->p2sh));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command newaddr_command = {
	"newaddr",
	json_newaddr,
	"Get a new address to fund a channel",
	"Returns {address} a p2sh address"
};
AUTODATA(json_command, &newaddr_command);

static void json_payback(struct command *cmd,
	const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *txtok, *addrstr;
	size_t txhexlen;
    char*  redeem_addr_str;
    bool   istestnet;
    struct bitcoin_address redeem_addr;
	struct bitcoin_tx *tx, *txout;
	u32 output;
	struct pubkey walletpubkey;
	u64 fee;
    u8* rawtransaction;

	if (!json_get_params(buffer, params, 
        "tx", &txtok,
        "?address", &addrstr,
		NULL)) {
		command_fail(cmd, "Need {raw tx} paid to our wallet address");
		return;
	}

    redeem_addr_str = addrstr ? tal_strndup(cmd, buffer + addrstr->start,
        addrstr->end - addrstr->start) : cmd->dstate->default_redeem_address;
    if (!redeem_addr_str)
    {
        command_fail(cmd, "No default redeem address specified");
        return;
    }

    if (!bitcoin_from_base58(&istestnet, &redeem_addr, redeem_addr_str,
        strlen(redeem_addr_str)))
    {
        command_fail(cmd, "Invalid redeem address %s", redeem_addr_str);
        return;
    }

    if (istestnet != cmd->dstate->testnet)
    {
        command_fail(cmd, "Not match for the nettype: is %s address", 
            (istestnet ? "[testnet]" : "[mainnet]"));
        return;
    }

	txhexlen = txtok->end - txtok->start;
	tx = bitcoin_tx_from_hex(cmd, buffer + txtok->start, txhexlen);
	if (!tx) {
		command_fail(cmd, "'%.*s' is not a valid transaction",
			txtok->end - txtok->start,
			buffer + txtok->start);
		return;
	}

	/* Find an output we know how to spend. */
	for (output = 0; output < tx->output_count; output++) {
		if (wallet_can_spend(cmd->dstate, &tx->output[output],
			&walletpubkey))
			break;
	}
	if (output == tx->output_count) {
		command_fail(cmd, "Tx doesn't send to wallet address");
		return;
	}

	/* construct the payback tx and broadcast */
	txout = bitcoin_tx(cmd, 1, 1);

    txout->output[0].script = 
        /*scriptpubkey_p2sh_p2wpkh(cmd, &redeem_addr)*/
        scriptpubkey_p2pkh(cmd, &redeem_addr);        

    txout->output[0].script_length = tal_count(txout->output[0].script);

    bitcoin_txid(tx, &txout->input[0].txid);
    txout->input[0].index = output;
    txout->input[0].amount = &tx->output[output].amount;

    /* FIXME: not exact, and round up */
    fee = fee_by_feerate(125, get_feerate(cmd->dstate));
    if (fee >= *txout->input[0].amount) {
        command_fail(cmd, "Amount %"PRIu64" below fee %"PRIu64,
            *txout->input[0].amount, fee);
        return;
    }

    txout->output[0].amount = *txout->input[0].amount - fee;

    if (!wallet_add_signed_input(cmd->dstate, &walletpubkey, txout, 0))
    {
        command_fail(cmd, "Sign tx input failed");
        return;
    }

    /* all done, just output the raw transaction */
    rawtransaction = linearize_tx(cmd, txout);

    json_object_start(response, NULL);
    json_add_string(response, "rawtransaction",
        tal_hexstr(cmd, rawtransaction, tal_count(rawtransaction)));
    json_object_end(response);
    command_success(cmd, response);

}

static const struct json_command payback_command = {
	"dbg-payback",
	json_payback,
	"Payback the coin in the hex-encoded {tx} output to our wallet to a specified address",
	"Returns an empty result on success"
};
AUTODATA(json_command, &payback_command);