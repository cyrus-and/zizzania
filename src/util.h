#ifndef ZZ_UTIL_H
#define ZZ_UTIL_H

#include "handler.h"

#define ZZ_STRING_BASE(x) #x
#define ZZ_STRING(x) ZZ_STRING_BASE(x)

int zz_drop_root(zz_handler *zz);

#endif
