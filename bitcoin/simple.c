#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "pubkey.h"

const unsigned char*  simple_pubkey_data(const struct pubkey* pk) { return pk->pubkey.data_uc; }
unsigned int    simple_pubkey_size(const struct pubkey* pk) { return pk->compressed ? sizeof(pk->pubkey.data) : sizeof(pk->pubkey.data_uc); }

const unsigned char*  simple_sha256_data(const struct sha256* s) { return s->u.u8; }

void            simple_freeobjects(void* p) { tal_free(p); }

