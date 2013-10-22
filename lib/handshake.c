#include <unistd.h>
#include <string.h>
#include "debug.h"
#include "killer.h"
#include "handshake.h"

#define EAPOL_FLAGS_MASK 0x0dc8
#define EAPOL_FLAGS_1 0x0088
#define EAPOL_FLAGS_2_4 0x0108
#define EAPOL_FLAGS_3 0x01c8

/* debug */
char bssid_str[18];
char source_str[18];
char destination_str[18];
char client_addr_str[18];

struct client {
    uint8_t need_set;
    int64_t start_counter;
};

struct client_info {
    uint64_t replay_counter;
    uint16_t flags;
};

static int zizzania_enqueue_dispatcher_action(struct zizzania *z, int action,
                                              const ieee80211_addr_t client,
                                              const ieee80211_addr_t bssid) {
    if (!z->setup.passive) {
        struct zizzania_killer_message message;

        /* prepare message */
        message.action = action;
        memcpy(message.client, client, 6);
        memcpy(message.bssid, bssid, 6);

        /* enqueue action */
        if (write(z->comm[1], &message,
                  sizeof(struct zizzania_killer_message)) == -1) {
            zizzania_set_error_messagef
                (z, "cannot communicate with the dispatcher");
            z->stop = 1;
            return 0;
        }
    }

    return 1;
}

static int zizzania_update(struct zizzania *z, const ieee80211_addr_t target,
                           const ieee80211_addr_t client_addr,
                           struct client *client,
                           const struct client_info *client_info) {
    int sequence;

    /* check EAPOL flags */
    switch (client_info->flags & EAPOL_FLAGS_MASK) {
    case EAPOL_FLAGS_1:
        sequence = 0;
        break;

    case EAPOL_FLAGS_2_4:
        /* return if it still needs the first packet, since cannot distinguish
           between 2 and 4 (replay_counter needed) */
        if (client->need_set & 1) {
            PRINT("waiting for handshake #1, "
                  "cannot distinguish between #2 and #4");
            return 1;
        }

        /* disambiguate */
        if (client_info->replay_counter == client->start_counter) {
            sequence = 1;
        } else if (client_info->replay_counter == client->start_counter + 1) {
            sequence = 3;
        } else {
            PRINT("skipping handshake #2 or #4 since it's part of another");
            return 1;
        }
        break;

    case EAPOL_FLAGS_3:
        sequence = 2;
        break;

    default:
        PRINTF("unrecognizable EAPOL flags 0x%04hx of %s @ %s",
                client_info->flags, source_str, bssid_str);
        return 1;
    }

    PRINTF("got handshake #%i for client %s @ %s",
           sequence + 1, client_addr_str, bssid_str);

    /* the first packet */
    if (sequence == 0) {
        /* reinitialize client */
        client->start_counter = client_info->replay_counter;
        client->need_set = 0xe; /* 0b1110 */
    }
    /* don't need the first */
    else if (!(client->need_set & 1)) {
        /* update information */
        client->need_set &= ~(1 << sequence);

        /* done with that client */
        if (client->need_set == 0) {
            PRINTF("got full handshake for client %s @ %s",
                   source_str, bssid_str);

            /* notify to the user */
            if (z->setup.on_handshake) {
                z->setup.on_handshake(target, client_addr);
            }

            /* notify to the dispatcher */
            return zizzania_enqueue_dispatcher_action(z, ZIZZANIA_HANDSHAKE,
                                                      client_addr, target);
        }
    }

    return 1;
}

int zizzania_process_packet(struct zizzania *z,
                            const struct pcap_pkthdr *pkt_header,
                            const uint8_t *pkt) {
    const uint8_t *orig_pkt = pkt;
    struct ieee80211_radiotap_header *radiotap_header;
    struct ieee80211_mac_header *mac_header;
    struct ieee8022_llc_snap_header *llc_snap_header;
    struct ieee8021x_authentication_header *authentication_header;
    ieee80211_addr_t bssid, source, destination, client_addr;

    /* skip radiotap header */
    radiotap_header = (struct ieee80211_radiotap_header *)pkt;
    pkt += radiotap_header->length;

    /* mac header */
    mac_header = (struct ieee80211_mac_header *)pkt;

    /* filter directions */
    if (mac_header->to_ds != mac_header->from_ds) {
        /* station to access point */
        if (mac_header->to_ds) {
            bssid = mac_header->address_1;
            source = mac_header->address_2;
            destination = mac_header->address_3;
            client_addr = source;
        }
        /* access point to station */
        else {
            destination = mac_header->address_1;
            bssid = mac_header->address_2;
            source = mac_header->address_3;
            client_addr = destination;
        }

        if (zz->setup.verbose) {
            /* prepare address strings */
            ieee80211_addr_sprint(bssid, bssid_str);
            ieee80211_addr_sprint(source, source_str);
            ieee80211_addr_sprint(destination, destination_str);
            ieee80211_addr_sprint(client_addr, client_addr_str);
        }

        /* skip broadcast/multicast frames */
        if (memcmp(destination, BROADCAST_MAC_ADDRESS, 6) != 0 &&
            memcmp(destination, IPV4_MULTICAST_MAC_ADDRESS_PFX,
                   IPV4_MULTICAST_MAC_ADDRESS_PFX_LENGTH) != 0 &&
            memcmp(destination, IPV6_MULTICAST_MAC_ADDRESS_PFX,
                   IPV6_MULTICAST_MAC_ADDRESS_PFX_LENGTH) != 0) {
            GHashTable *clients;

            /* automatically add target */
            if (z->setup.auto_add_targets) {
                if (zizzania_add_target(z, bssid)) {
                    PRINTF("automatically adding target %s", bssid_str);
                }
            }

            /* fetch client hashtable for this target */
            clients = g_hash_table_lookup(z->targets, bssid);

            /* check if interested in that target (useless when
               auto_add_targets) */
            if (clients) {
                struct client *client;

                /* add the new client to the hashtable */
                client = g_hash_table_lookup(clients, client_addr);
                if (!client) {
                    PRINTF("adding new client %s", client_addr_str);

                    /* notify to the user */
                    if (z->setup.on_new_client) {
                        z->setup.on_new_client(bssid, client_addr);
                    }

                    /* notify to the dispatcher */
                    if (!zizzania_enqueue_dispatcher_action
                        (z, ZIZZANIA_NEW_CLIENT, client_addr, bssid)) {
                        return 0;
                    }

                    /* initialize client */
                    client = g_new(struct client, 1);
                    client->need_set = 0xf; /* 0b1111 */

                    /* add it */
                    g_hash_table_insert(clients,
                                        g_memdup(client_addr, 6), client);
                }

                /* llc+snap header */
                pkt += sizeof(struct ieee80211_mac_header)
                    + (pkt[0] == 0x88 ? 2 : 0); /* (2 more byte if qos data) */
                llc_snap_header = (struct ieee8022_llc_snap_header *)pkt;

                /* check snap+eapol presence */
                if (llc_snap_header->dsap == 0xaa &&
                    llc_snap_header->ssap == 0xaa &&
                    llc_snap_header->control == 0x03 &&
                    /* ieee8021x_authentication_header*/
                    llc_snap_header->type == htobe16(0x888e)) {
                    struct client_info client_info;

                    /* dump every eapol packets anyway this is a quick and dirty
                       way to cope with reconnections */
                    if (z->dumper) {
                        pcap_dump((u_char *)z->dumper, pkt_header, orig_pkt);
                    }

                    /* eapol message for finished clients triggers a reset since
                       it's probably a reconnection so a new full handshake is
                       needed */
                    if (!client->need_set) {
                        PRINTF("possible reconnection of client %s",
                               client_addr_str);

                        /* notify to the dispatcher */
                        zizzania_enqueue_dispatcher_action
                            (z, ZIZZANIA_NEW_CLIENT, client_addr, bssid);

                        /* reinitialize client */
                        client->need_set = 0xf; /* 0b1111 */
                    }

                    /* EAPOL header */
                    pkt += sizeof(struct ieee8022_llc_snap_header);
                    authentication_header =
                        (struct ieee8021x_authentication_header *)pkt;

                    /* get interesting values */
                    client_info.replay_counter =
                        be64toh(authentication_header->replay_counter);
                    client_info.flags = be16toh(authentication_header->flags);

                    /* update with this packet */
                    zizzania_update (z, bssid, client_addr,
                                     client, &client_info);
                } else {
#if DEBUG
                    PRINTF("skipping invalid SNAP+EAPOL frame "
                           "(DSAP: 0x%02x, SSAP: 0x%02x, "
                           "control: 0x%02x, ULP: 0x%04hx) "
                           "from %s to %s @ %s",
                           llc_snap_header->dsap, llc_snap_header->ssap,
                           llc_snap_header->control,
                           htobe16(llc_snap_header->type),
                           source_str, destination_str, bssid_str);
#endif

                    /* dump non eapol packets for finished clients only */
                    if (!client->need_set && z->dumper) {
                        pcap_dump((u_char *)z->dumper, pkt_header, orig_pkt);
                    }
                }
            }
#if DEBUG
            else {
                PRINTF("skipping target %s", bssid_str);
            }
#endif
        }
#if DEBUG
        else {
            PRINTF("skipping broadcast message from %s @ %s",
                   source_str, bssid_str);
        }
#endif
    }
#if DEBUG
    else {
        PRINT("skipping message due to frame direction");
    }
#endif

    return 1;
}
