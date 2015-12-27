#ifndef ZZ_DISPATCHER_H
#define ZZ_DISPATCHER_H

#include <pthread.h>

#include "handler.h"

int zz_dispatcher_start(zz_handler *zz, pthread_t *thread);

#endif
