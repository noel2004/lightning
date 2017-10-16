#ifndef LIGHTNING_BITCOIN_SIMPLE_H
#define LIGHTNING_BITCOIN_SIMPLE_H

#ifdef __cplusplus
extern "C"{
#endif

    struct pubkey;
#define SIMPLE_PUBKEY_DATASIZE 33
    const unsigned char*  simple_pubkey_data(const struct pubkey*);
    unsigned int    simple_pubkey_size(const struct pubkey*);
    //only create short (33bytes) pubkey
    struct pubkey*  simple_pubkey_create(void* ctx, const unsigned char*);

    struct sha256;
    struct sha256_double;
    struct ecdsa_signature_;
#define SIMPLE_SHA256_DATASIZE 32
    const unsigned char*  simple_sha256_data(const struct sha256*);
    const unsigned char*  simple_sha256double_data(const struct sha256_double*);
    struct sha256*  simple_sha256_create(void* ctx, const unsigned char*);
    struct sha256_double*  simple_sha256double_create(void* ctx, const unsigned char*);

    struct ecdsa_signature_;
#define SIMPLE_ECDSA_DATASIZE 64
    const unsigned char*  simple_ecdsasig_data(const struct ecdsa_signature_*);
    struct ecdsa_signature_* simple_ecdsasig_create(void* ctx, const unsigned char*);

    void            simple_freeobjects(void*);

#ifdef __cplusplus
}
#endif

#endif /* LIGHTNING_BITCOIN_SIMPLE_H */
