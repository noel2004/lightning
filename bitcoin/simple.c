#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "pubkey.h"
#include "shadouble.h"
#include "signature.h"

const unsigned char*  simple_pubkey_data(const struct pubkey* pk) { return pk->pubkey.data_uc; }
unsigned int    simple_pubkey_size(const struct pubkey* pk) { return pk->compressed ? sizeof(pk->pubkey.data) : sizeof(pk->pubkey.data_uc); }

const unsigned char*  simple_sha256_data(const struct sha256* s) { return s->u.u8; }
const unsigned char*  simple_sha256double_data(const struct sha256_double* s) { return s->sha.u.u8; }
const unsigned char*  simple_ecdsasig_data(const struct ecdsa_signature_* s) { return s->data; }

struct pubkey*  simple_pubkey_create(void* ctx, const unsigned char* u)
{

}

struct sha256*  simple_sha256_create(void* ctx, const unsigned char* u){}
struct sha256_double*  simple_sha256double_create(void* ctx, const unsigned char* u){}
struct ecdsa_signature_* simple_ecdsasig_create(void* ctx, const unsigned char* u){}

void            simple_freeobjects(void* p) { tal_free(p); }

