#include <errno.h>
#include <string.h>
#include "debug.h"
#include "zizzania.h"
#include "killer.h"
#include "dispatcher.h"

#define DISPATCHER_TIMEOUT 5

void * zz_dispatcher(void *arg) {
    zz_t *zz = arg;
    sigset_t set;
    struct timespec timeout = {0};

    /* prepare timed wait */
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    timeout.tv_sec = DISPATCHER_TIMEOUT;

    /* wait for events */
    while (!zz->stop) {
        switch (errno = 0, sigtimedwait(&set, NULL, &timeout)) {
        case SIGINT:
        case SIGTERM:
            PRINT("signal catched");
            zz->stop = 1;
            continue;

        case -1:
            /* restart system call after a signal */
            if (errno == EINTR) continue;

            /* start the killer after a timeout */
            if (errno == EAGAIN) break;
        }

        /* deauthenticate clients (if not passive) */
        if (!zz->setup.passive) {
            if (!zz_start_killer(zz)) {
                zz->stop = 1;
                return (void *)0;
            }
        }
    }

    return (void *)1;
}
