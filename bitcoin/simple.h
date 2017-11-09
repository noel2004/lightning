#ifndef LIGHTNING_BITCOIN_SIMPLE_H
#define LIGHTNING_BITCOIN_SIMPLE_H

#ifndef BTCSIMPLE_API
# if defined(_WIN32)
#  ifdef LNCORE_BUILD
#   define BTCSIMPLE_API __declspec(dllexport)
#  elif defined(LNCORE_USED)
#   define BTCSIMPLE_API __declspec(dllimport)
#  else
#   define BTCSIMPLE_API
#  endif
# elif defined(__GNUC__) && defined(LNCORE_BUILD)
#  define BTCSIMPLE_API __attribute__ ((visibility ("default")))
# else
#  define BTCSIMPLE_API
# endif
#endif

#ifdef __cplusplus
extern "C"{
#endif

    struct pubkey;
#define SIMPLE_PUBKEY_DATASIZE 33
BTCSIMPLE_API    const unsigned char*  simple_pubkey_data(const struct pubkey*);
BTCSIMPLE_API    unsigned int    simple_pubkey_size(const struct pubkey*);
    //only create short (33bytes) pubkey
BTCSIMPLE_API    struct pubkey*  simple_pubkey_create(void* ctx, const unsigned char*);

    struct sha256;
    struct sha256_double;
    struct ecdsa_signature_;
#define SIMPLE_SHA256_DATASIZE 32
BTCSIMPLE_API    const unsigned char*  simple_sha256_data(const struct sha256*);
BTCSIMPLE_API    const unsigned char*  simple_sha256double_data(const struct sha256_double*);
BTCSIMPLE_API    struct sha256*  simple_sha256_create(void* ctx, const unsigned char*);
BTCSIMPLE_API    struct sha256_double*  simple_sha256double_create(void* ctx, const unsigned char*);

    struct preimage;
#define SIMPLE_PREIMAGE_DATASIZE 32
BTCSIMPLE_API    const unsigned char*  simple_preimage_data(const struct preimage*);
BTCSIMPLE_API    struct preimage*  simple_preimage_create(void* ctx, const unsigned char*);

    struct ecdsa_signature_;
#define SIMPLE_ECDSA_DATASIZE 64
BTCSIMPLE_API    const unsigned char*  simple_ecdsasig_data(const struct ecdsa_signature_*);
BTCSIMPLE_API    struct ecdsa_signature_* simple_ecdsasig_create(void* ctx, const unsigned char*);

BTCSIMPLE_API    void  simple_freeobjects(const void*);

#ifdef __cplusplus
}
#endif

#endif /* LIGHTNING_BITCOIN_SIMPLE_H */
