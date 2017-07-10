#include "failure.h"
#include <ccan/tal/str/str.h>

/* FIXME: Crypto! */
const u8 *failinfo_create(const tal_t *ctx,
			  const struct pubkey *id,
			  u32 error_code,
			  const char *reason)
{
	return tal_strdup(ctx, reason);
}


