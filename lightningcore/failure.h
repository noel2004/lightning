#ifndef LIGHTNING_CORE_FAILURE_H
#define LIGHTNING_CORE_FAILURE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct pubkey;

enum fail_error {
	BAD_REQUEST_400 = 400,
	UNAUTHORIZED_401 = 401,
	PAYMENT_REQUIRED_402 = 402,
	FORBIDDEN_403 = 403,
	NOT_FOUND_404 = 404,
	METHOD_NOT_ALLOWED_405 = 405,
	REQUEST_TIMEOUT_408 = 408,
	GONE_410 = 410,
	IM_A_TEAPOT_418 = 418,
	INTERNAL_SERVER_ERROR_500 = 500,
	NOT_IMPLEMENTED_501 = 501,
	BAD_GATEWAY_502 = 502,
	SERVICE_UNAVAILABLE_503 = 503,
	GATEWAY_TIMEOUT_504 = 504,
	VERSION_NOT_SUPPORTED_505 = 505
};

//create a JSON string for failure description
const u8 *failinfo_create(const tal_t *ctx,
			  const struct pubkey *id,
			  enum fail_error error_code,
			  const char *reason);

#endif /* LIGHTNING_CORE_FAILURE_H */
