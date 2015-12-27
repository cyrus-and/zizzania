#ifdef __APPLE__

#include <errno.h>

#include "handler.h"

int zz_set_monitor(zz_handler *zz) {
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

#define IFREQ_FLAGS_DOWN 0
#define IFREQ_FLAGS_UP IFF_UP | IFF_BROADCAST | IFF_RUNNING

static int ifreq_flags(int fd, const char *iface, short flags) {
    struct ifreq ifreq;

    memset(&ifreq, 0, sizeof(struct ifreq));
    strncpy(ifreq.ifr_name,iface, IFNAMSIZ);
    ifreq.ifr_flags = flags;
    return ioctl(fd, SIOCSIFFLAGS, &ifreq) == 0;
}

static int iwreq_mode(int fd, const char *iface, __u32 mode) {
    struct iwreq iwreq;

    memset(&iwreq, 0, sizeof(struct iwreq));
    strncpy(iwreq.ifr_name, iface, IFNAMSIZ);
    iwreq.u.mode = mode;
    return (ioctl(fd, SIOCSIWMODE, &iwreq) == 0);
}

static int iwreq_freq(int fd, const char *iface, int channel) {
    struct iwreq iwreq;

    memset(&iwreq, 0, sizeof(struct iwreq));
    strncpy(iwreq.ifr_name, iface, IFNAMSIZ);
    iwreq.u.freq.m = channel;
    iwreq.u.freq.e = 0;
    return (ioctl(fd, SIOCSIWFREQ, &iwreq) == 0);
}

int zz_set_monitor(zz_handler *zz) {
    int fd;

    assert(zz->setup.is_live);
    assert(zz->setup.channel > 0);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return 0;
    }

    return (ifreq_flags(fd, zz->setup.input, IFREQ_FLAGS_DOWN) &&
            iwreq_mode(fd, zz->setup.input, IW_MODE_MONITOR) &&
            ifreq_flags(fd, zz->setup.input, IFREQ_FLAGS_UP) &&
            iwreq_freq(fd, zz->setup.input, zz->setup.channel));
}

#endif
