#ifndef ZZ_PARAMS_H
#define ZZ_PARAMS_H

/* seconds to wait for natural handshake completion before start
 * deauthenticating a client */
#define ZZ_KILLER_GRACE_TIME 3

/* microseconds after which handshake information are considered ivalid if
 * another handshake message arrives */
#define ZZ_MAX_HANDSHAKE_TIME 500000

#endif

