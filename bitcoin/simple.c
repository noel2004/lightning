#include "config.h"
#include "simple.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "pubkey.h"
#include "shadouble.h"
#include "signature.h"
#include "preimage.h"

const unsigned char*  simple_pubkey_data(const struct pubkey* pk) { return pk->pubkey.data_uc; }
unsigned int    simple_pubkey_size(const struct pubkey* pk) { return pk->compressed ? sizeof(pk->pubkey.data) : sizeof(pk->pubkey.data_uc); }

const unsigned char*  simple_sha256_data(const struct sha256* s) { return s->u.u8; }
const unsigned char*  simple_sha256double_data(const struct sha256_double* s) { return s->sha.u.u8; }
const unsigned char*  simple_ecdsasig_data(const struct ecdsa_signature_* s) { return s->data; }
const unsigned char*  simple_preimage_data(const struct preimage* r) { return r->r; }

struct pubkey*  simple_pubkey_create(void* ctx, const unsigned char* u)
{
    struct pubkey *pk = pubkey_create_btc(ctx, false);
    memcpy(pk->pubkey.data, u, SIMPLE_PUBKEY_DATASIZE);
    return pk;
}

#define SIMPLE_CREATE_TYPE(M, T, SZ) T *p = talz(ctx, T);memcpy(p->M, u, SZ);return p
struct sha256*  simple_sha256_create(void* ctx, const unsigned char* u) {SIMPLE_CREATE_TYPE(u.u8, struct sha256, SIMPLE_SHA256_DATASIZE);}
struct sha256_double*  simple_sha256double_create(void* ctx, const unsigned char* u){ SIMPLE_CREATE_TYPE(sha.u.u8, struct sha256_double, SIMPLE_SHA256_DATASIZE); }
struct ecdsa_signature_* simple_ecdsasig_create(void* ctx, const unsigned char* u){ SIMPLE_CREATE_TYPE(data, struct ecdsa_signature_, SIMPLE_ECDSA_DATASIZE); }
struct preimage*  simple_preimage_create(void* ctx, const unsigned char* u){ SIMPLE_CREATE_TYPE(r, struct preimage, SIMPLE_PREIMAGE_DATASIZE); }

void            simple_freeobjects(void* p) { tal_free(p); }

