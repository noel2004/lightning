/* Converted to C by Rusty Russell, based on bitcoin source: */
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "privkey.h"
#include "pubkey.h"
#include "shadouble.h"
#include "utils/utils.h"
#include "include/wally_core.h"
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/tal/str/str.h>
#include <string.h>

static bool test_net = false;

static bool my_sha256(void *digest, const void *data, size_t datasz)
{
	sha256(digest, data, datasz);
	return true;
}

static char *to_base58(const tal_t *ctx, u8 version,
		       const unsigned char *bytes, unsigned int byteslen)
{
    char *outstr;
    char *ret;
    size_t inlen = byteslen + 1;
    unsigned char* out = tal_arr(ctx, unsigned char, inlen);
    out[0] = version;
    memcpy(out + 1, bytes, byteslen);
    if (wally_base58_from_bytes(bytes, inlen, BASE58_FLAG_CHECKSUM, &outstr) != WALLY_OK) {
        return NULL;
    }

    ret = tal_strdup(ctx, outstr);
    wally_free_string(outstr);

    return ret;
}

void bitcoin_use_testnet(bool b) { test_net = b; }

char *bitcoin_to_base58(const tal_t *ctx, 
			const struct bitcoin_address *addr)
{
	return to_base58(ctx, test_net ? 111 : 0, addr->addr, sizeof(addr->addr));
}

char *p2sh_to_base58(const tal_t *ctx, 
		     const struct bitcoin_address *p2sh)
{
	return to_base58(ctx, test_net ? 196 : 5, p2sh->addr, sizeof(p2sh->addr));
}

static bool from_base58(u8 *version,
			struct bitcoin_address *rmd,
			const char *base58, size_t base58_len)
{
    u8 buf[1 + sizeof(rmd->addr)];
    size_t outlen = 0;

    if (wally_base58_to_bytes(base58, BASE58_FLAG_CHECKSUM, buf, sizeof(buf), &outlen)
        != WALLY_OK) {
        return false;
    }

    memset(rmd->addr, 0, sizeof(rmd->addr));
    *version = buf[0];
    memcpy(rmd->addr, buf + 1, outlen - 1);

    return true;
}

bool bitcoin_from_base58(struct bitcoin_address *addr,
			 const char *base58, size_t len)
{
	u8 version;

	if (!from_base58(&version, addr, base58, len))
		return false;

    if (version == 111)
        return test_net;
	else if (version == 0)
        return !test_net;
	else
		return false;

}

bool p2sh_from_base58(struct bitcoin_address *p2sh,
		      const char *base58, size_t len)
{
	u8 version;

	if (!from_base58(&version, p2sh, base58, len))
		return false;

	if (version == 196)
        return test_net;
	else if (version == 5)
        return !test_net;
	else
		return false;

}


char *key_to_base58(const tal_t *ctx, const struct privkey *key)
{
    return to_base58(ctx, test_net ? 239 : 128, key->secret.data, sizeof(key->secret.data));
}

bool key_from_base58(const char *base58, size_t base58_len, 
    struct privkey *priv, struct pubkey *key)
{
	//// 1 byte version, 32 byte private key, 1 byte compressed, 4 byte checksum
	//u8 keybuf[1 + 32 + 1 + 4];
	//size_t keybuflen = sizeof(keybuf);

	//b58_sha256_impl = my_sha256;

	//b58tobin(keybuf, &keybuflen, base58, base58_len);
	//if (b58check(keybuf, sizeof(keybuf), base58, base58_len) < 0)
	//	return false;

	///* Byte after key should be 1 to represent a compressed key. */
	//if (keybuf[1 + 32] != 1)
	//	return false;

	//if (keybuf[0] == 128)
	//	*test_net = false;
	//else if (keybuf[0] == 239)
	//	*test_net = true;
	//else
	//	return false;

	///* Copy out secret. */
	//memcpy(priv->secret.data, keybuf + 1, sizeof(priv->secret.data));

	//if (!secp256k1_ec_seckey_verify(secp256k1_ctx, priv->secret.data))
	//	return false;

	///* Get public key, too. */
	//if (!pubkey_from_privkey(priv, key))
	//	return false;

	return false;
}
