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

static pcap_t *pcap = NULL;

static void terminate_pcap_loop(int signum) {
    pcap_breakloop(pcap);
}

static void *dispatcher(void *_zz) {
    zz_handler *zz = _zz;
    sigset_t set;
    struct itimerval timer;
    int error;

    /* prepare signal mask */
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGALRM);

    /* prepare the repeated alarm */
    memset(&timer, 0, sizeof(struct itimerval));
    timer.it_value.tv_sec = DISPATCHER_TIMEOUT;
    timer.it_interval.tv_sec = DISPATCHER_TIMEOUT;
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);

    /* dispatcher loop */
    error = 0;
    while (!zz->is_done) {
        int signal;

        /* wait for the next signal or timeout */
        assert(sigwait(&set, &signal) == 0);
        switch (signal) {
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
            /* this signal is also used in passive mode to wake up the
             * dispatcher and check for the termination */
            if (!zz->setup.is_passive) {
                /* wake the killer at regular intervals */
                if (!zz_killer_run(zz, &zz->killer)) {
                    error = zz->is_done = 1;
                }
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
    struct sigaction sa = {0};
    sigset_t set;

    /* set up the pcap termination handler */
    pcap = zz->pcap;
    sa.sa_handler = terminate_pcap_loop;
    assert(sigaction(SIGINT, &sa, NULL) == 0);
    assert(sigaction(SIGTERM, &sa, NULL) == 0);

    /* mask all signals of the calling thread except for termination-related
     * ones that must terminate the pcap loop */
    sigfillset(&set);
    sigdelset(&set, SIGINT);
    sigdelset(&set, SIGTERM);
    assert(pthread_sigmask(SIG_SETMASK, &set, NULL) == 0);

    /* start the dispatcher */
    zz_log("Starting the dispatcher thread");
    assert(pthread_create(thread, NULL, dispatcher, zz) == 0);
    return 1;
}
