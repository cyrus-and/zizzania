#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>

#include "dispatcher.h"
#include "handler.h"
#include "killer.h"
#include "terminal.h"

#define DISPATCHER_TIMEOUT 1 /* seconds */

int zz_killer_run(zz_handler *zz, zz_killer *killer); /* to avoid circular deps */

static void *dispatcher(void *arg) {
    zz_handler *zz = arg;
    sigset_t set;
    struct itimerval timer;
    int error;

    /* prepare signal mask */
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGUSR1);

    /* prepare the repeated alarm */
    if (!zz->setup.is_passive) {
        sigaddset(&set, SIGALRM);
        memset(&timer, 0, sizeof(struct itimerval));
        timer.it_value.tv_sec = DISPATCHER_TIMEOUT;
        timer.it_interval.tv_sec = DISPATCHER_TIMEOUT;
        assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    }

    /* dispatcher loop */
    error = 0;
    while (!zz->is_done) {
        int signal;

        /* wait for the next signal */
        assert(sigwait(&set, &signal) == 0);
        switch (signal) {
        case SIGINT:
        case SIGTERM:
            zz_log("Terminating due to signal %d", signal);
            zz->is_done = 1;
            break;

        case SIGUSR1:
            if (zz->setup.is_verbose) {
                zz_log("Verbose logging disabled");
                zz->setup.is_verbose = 0;
            } else {
                zz->setup.is_verbose = 1;
                zz_log("Verbose logging enabled");
            }
            break;

        case SIGALRM:
            /* wake the killer at regular intervals */
            if (!zz_killer_run(zz, &zz->killer)) {
                error = zz->is_done = 1;
            }
            break;
        }
    }

    /* reset the alarm */
    if (!zz->setup.is_passive) {
        memset(&timer, 0, sizeof(struct itimerval));
        assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    }

    return (error ? (void *)0 : (void *)1);
}

int zz_dispatcher_start(zz_handler *zz, pthread_t *thread) {
    sigset_t set;

    /* mask all signals of the calling thread */
    sigfillset(&set);
    assert(pthread_sigmask(SIG_SETMASK, &set, NULL) == 0);

    /* start the dispatcher */
    zz_log("Starting the dispatcher thread");
    assert(pthread_create(thread, NULL, dispatcher, zz) == 0);
    return 1;
}
