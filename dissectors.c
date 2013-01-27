#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dissectors.h"

guint ieee80211_addr_hash(gconstpointer key) {
    uint32_t a = *(guint *)key;
    uint32_t b = *((guint *)((uint8_t *)key + 2));

    return a ^ b;
}

gboolean ieee80211_addr_equal(gconstpointer a, gconstpointer b) {
    return memcmp(a, b, 6) == 0;
}

void ieee80211_addr_sprint(const ieee80211_addr_t addr, char buffer[18]) {
    sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

int ieee80211_addr_sscan(ieee80211_addr_t addr, const char buffer[18]) {
    int i;

    for (i = 0; i < 6; buffer += 3, i++) {
        char *chk;

        addr[i] = strtol(buffer, &chk, 16);
        if ((*chk != ':' && *chk != '\0') || chk - buffer != 2) {
            return 0;
        }
    }

    return 1;
}
