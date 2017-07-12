#ifndef LIGHTNING_CORE_CHANNELSTATE_NAMES_H
#define LIGHTNING_CORE_CHANNELSTATE_NAMES_H
#include "config.h"
#include "state_types.h"

const char *state_name(enum state s);
enum state name_to_state(const char *name);

#endif /* LIGHTNING_CORE_CHANNELSTATE_NAMES_H */
