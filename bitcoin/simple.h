#ifndef LIGHTNING_BITCOIN_SIMPLE_H
#define LIGHTNING_BITCOIN_SIMPLE_H

#ifdef __cplusplus
extern "C"{
#endif

    struct pubkey;
#define SIMPLE_PUBKEY_DATASIZE 33
    const unsigned char*  simple_pubkey_data(const struct pubkey*);
    unsigned int    simple_pubkey_size(const struct pubkey*);

    struct sha256;
#define SIMPLE_SHA256_DATASIZE 32
    const unsigned char*  simple_sha256_data(const struct sha256*);

    void            simple_freeobjects(void*);

#ifdef __cplusplus
}
#endif

#endif /* LIGHTNING_BITCOIN_SIMPLE_H */
