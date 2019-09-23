#ifdef __APPLE__

#include <errno.h>

#include "handler.h"

int zz_set_channel(zz_handler *zz) {
    errno = ENOTSUP;
    return 0;
}

#else

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/wireless.h>

#include "handler.h"

static int iwreq_freq(int fd, const char *iface, int channel) {
    struct iwreq iwreq;

    memset(&iwreq, 0, sizeof(struct iwreq));
    strncpy(iwreq.ifr_name, iface, IFNAMSIZ);
    iwreq.u.freq.m = channel;
    iwreq.u.freq.e = 0;
    return (ioctl(fd, SIOCSIWFREQ, &iwreq) == 0);
}

int zz_set_channel(zz_handler *zz) {
    int fd;

    assert(zz->setup.is_live);
    assert(zz->setup.channel > 0);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return 0;
    }

    return iwreq_freq(fd, zz->setup.input, zz->setup.channel);
}

#endif
