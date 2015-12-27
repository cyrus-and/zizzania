#ifndef ZZ_KILLER_H
#define ZZ_KILLER_H

#include "ieee802.h"

struct zz_target;

typedef struct {
    struct zz_target *targets;
    int pipe[2];
} zz_killer;

void zz_killer_new(zz_killer *killer);
void zz_killer_free(zz_killer *killer);

#endif
