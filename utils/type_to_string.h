#ifndef LIGHTNING_TYPE_TO_STRING_H
#define LIGHTNING_TYPE_TO_STRING_H
#include "config.h"
#include "utils.h"
#include <ccan/autodata/autodata.h>

/* This must match the type_to_string_ cases. */
union printable_types {
	const struct pubkey *pubkey;
	const struct sha256_double *sha256_double;
	const struct sha256 *sha256;
	const struct rel_locktime *rel_locktime;
	const struct abs_locktime *abs_locktime;
	const struct bitcoin_tx *bitcoin_tx;
	const struct htlc *htlc;
	const struct preimage *preimage;
	const struct channel_state *channel_state;
	const struct channel_oneside *channel_oneside;
	const struct channel_id *channel_id;
	const struct short_channel_id *short_channel_id;
	const struct secret *secret;
	const struct privkey *privkey;
	const struct ecdsa_signature_ *ecdsa_signature_;
	const struct channel *channel;
	const char *charp_;
};

#if _MSC_VER <= 1900

static inline union printable_types to_printable_types_(const void* p) {
    union printable_types ret;
    memcpy(&ret, p, sizeof(p));
    return ret;
}

#define to_printable_types(type, ptr) to_printable_types_(ptr)

#else

#define to_printable_types(type, ptr) ((union printable_types)((const type *)ptr))

#endif

#define type_to_string(ctx, type, ptr)					\
	type_to_string_((ctx), stringify(type),				\
			((void)sizeof((ptr) == (type *)NULL),		\
			 to_printable_types(type, ptr)))

char *type_to_string_(const tal_t *ctx, const char *typename,
		      union printable_types u);

#define REGISTER_TYPE_TO_STRING(typename, fmtfn)			\
	static char *fmt_##typename##_(const tal_t *ctx,		\
				       union printable_types u)		\
	{								\
		return fmtfn(ctx, u.typename);				\
	}								\
	static struct type_to_string ttos_##typename = {		\
		#typename, fmt_##typename##_				\
	};								\
	AUTODATA(type_to_string, &ttos_##typename)

#define REGISTER_TYPE_TO_HEXSTR(typename)				\
	static char *fmt_##typename##_(const tal_t *ctx,		\
				       union printable_types u)		\
	{								\
		return tal_hexstr(ctx, u.typename, sizeof(*u.typename)); \
	}								\
	static struct type_to_string ttos_##typename = {		\
		#typename, fmt_##typename##_				\
	};								\
	AUTODATA(type_to_string, &ttos_##typename)

struct type_to_string {
	const char *typename;
	char *(*fmt)(const tal_t *ctx, union printable_types u);
};
AUTODATA_TYPE(type_to_string, struct type_to_string);
#endif /* LIGHTNING_UTILS_H */
