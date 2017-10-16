#include "address.h"
#include "privkey.h"
#include "pubkey.h"
#include "utils/type_to_string.h"
#include "utils/utils.h"
#include "include/wally_crypto.h"
#include <assert.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>

//bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key)
//{
//	if (len != PUBKEY_DER_LEN)
//		return false;
//
//	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &key->pubkey,
//				       memcheck(der, len), len))
//		return false;
//
//	return true;
//}
//
//void pubkey_to_der(u8 der[PUBKEY_DER_LEN], const struct pubkey *key)
//{
//	size_t outlen = PUBKEY_DER_LEN;
//	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outlen,
//					   &key->pubkey,
//					   SECP256K1_EC_COMPRESSED))
//		abort();
//	assert(outlen == PUBKEY_DER_LEN);
//}

/* Pubkey from privkey */
bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key)
{
    key->compressed = true;
    key->sign_type = EC_FLAG_ECDSA;
    return wally_ec_public_key_from_private_key(privkey->secret.data,
        sizeof(privkey->secret.data), key->pubkey.data, sizeof(key->pubkey.data))
        == WALLY_OK;

	return true;
}

bool pubkey_from_hexstr(const char *derstr, size_t slen, struct pubkey *key)
{
	size_t dlen;

    key->sign_type = EC_FLAG_ECDSA;

	dlen = hex_data_size(slen);
    if (dlen == EC_PUBLIC_KEY_LEN)
        key->compressed = true;
    else if (dlen == EC_PUBLIC_KEY_UNCOMPRESSED_LEN)
        key->compressed = false;
    else
        return false;

    return !hex_decode(derstr, slen, &key->pubkey, dlen);
}

struct pubkey *pubkey_create_btc(const tal_t *ctx, bool compressed)
{
    struct pubkey *pk = talz(ctx, struct pubkey);
    pk->sign_type = EC_FLAG_ECDSA;
    pk->compressed = compressed;

    return pk;
}

char *pubkey_to_hexstr(const tal_t *ctx, const struct pubkey *key)
{
	return tal_hexstr(ctx, &key->pubkey, key->compressed ? EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
}


bool pubkey_eq(const struct pubkey *a, const struct pubkey *b)
{
    return pubkey_cmp(a, b) == 0;
}

REGISTER_TYPE_TO_STRING(pubkey, pubkey_to_hexstr);

int pubkey_cmp(const struct pubkey *a, const struct pubkey *b)
{
	u8 keya[EC_PUBLIC_KEY_UNCOMPRESSED_LEN], keyb[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    const u8 *pa, *pb;

    if (a->compressed) {
        wally_ec_public_key_decompress(a->pubkey.data, sizeof(a->pubkey.data),
            keya, sizeof(keya));
        pa = keya;
    }
    else
        pa = a->pubkey.data_uc;

    if (b->compressed) {
        wally_ec_public_key_decompress(b->pubkey.data, sizeof(b->pubkey.data),
            keyb, sizeof(keyb));
    }
    else
        pb = b->pubkey.data_uc;

	return memcmp(pa, pb, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
}

static char *privkey_to_hexstr(const tal_t *ctx, const struct privkey *secret)
{
	/* Bitcoin appends "01" to indicate the pubkey is compressed. */
	char *str = tal_arr(ctx, char, hex_str_size(sizeof(*secret) + 1));
	hex_encode(secret, sizeof(*secret), str, hex_str_size(sizeof(*secret)));
	strcat(str, "01");
	return str;
}
REGISTER_TYPE_TO_STRING(privkey, privkey_to_hexstr);
REGISTER_TYPE_TO_HEXSTR(secret);

void pubkey_to_hash160(const struct pubkey *pk, struct bitcoin_address *hash)
{
    if (wally_hash160(pk->compressed ? pk->pubkey.data : pk->pubkey.data_uc,
        pk->compressed ? sizeof(pk->pubkey.data) : sizeof(pk->pubkey.data_uc),
        hash->addr, sizeof(hash->addr)) != WALLY_OK) {
        memset(hash->addr, 0, sizeof(hash->addr));
    }

}
