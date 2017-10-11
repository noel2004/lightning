#ifndef LIGHTNING_BITCOIN_SIMPLE_H
#define LIGHTNING_BITCOIN_SIMPLE_H

struct pubkey;
#define SIMPLE_PUBKEY_DATASIZE 33
unsigned char*  simple_pubkey_data(struct pubkey*);
unsigned int    simple_pubkey_size(struct pubkey*);

struct sha256;
#define SIMPLE_SHA256_DATASIZE 32
unsigned char*  simple_sha256_data(struct sha256*);

void            simple_freeobjects(void*);

#endif /* LIGHTNING_BITCOIN_SIMPLE_H */
