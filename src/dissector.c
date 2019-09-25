#include "dissector.h"
#include "handshake.h"
#include "ieee802.h"
#include "terminal.h"

#define TV_TO_SEC(tv) ((tv).tv_sec + (tv).tv_usec / 1000000.)

#define log_ts(format, ...) \
    zz_log("%.3f - " format, \
           TV_TO_SEC(packet_header->ts) - zz->epoch, ##__VA_ARGS__)

static void get_ssid(const uint8_t *params, uint32_t length,
                     const char **ssid, int *ssid_length) {
    const uint8_t *ptr;

    *ssid = NULL; /* valgrind happy when ssid_length is 0 */
    *ssid_length = 0;
    ptr = params;
    while (ptr < params + length) {
        uint8_t param_type;
        uint8_t param_length;

        param_type = *ptr++;
        param_length = *ptr++;
        if (param_type == ZZ_BEACON_SSID_PARAM_TYPE) {
            *ssid_length = param_length;
            *ssid = (const char *)ptr;
            return;
        }

        ptr += param_length;
    }
}

void zz_dissect_packet(zz_handler *zz, const struct pcap_pkthdr *packet_header,
                       const uint8_t *packet) {
    struct ieee80211_radiotap_header *radiotap_header;
    struct ieee80211_mac_header *mac_header;
    struct ieee8022_llc_snap_header *llc_snap_header;
    struct ieee8021x_authentication_header *authentication_header;
    char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];
    char source_str[ZZ_MAC_ADDR_STRING_SIZE];
    char destination_str[ZZ_MAC_ADDR_STRING_SIZE];
    char station_str[ZZ_MAC_ADDR_STRING_SIZE];
    zz_mac_addr bssid, source, destination, station;
    const uint8_t *cursor;
    uint32_t safe_size;
    int is_beacon;
    int is_eapol;
    zz_bss *bss;
    zz_packet_outcome outcome;
    const char *extra_info;

    /* save the timestamp of the first packet as a reference */
    if (!zz->epoch) {
        zz->epoch = TV_TO_SEC(packet_header->ts);
    }

    /* check size */
    safe_size = sizeof(struct ieee80211_radiotap_header);
    if (packet_header->caplen < safe_size) {
        log_ts("Skipping too short packet %u bytes", packet_header->caplen);
        return;
    }

    cursor = packet;

    /* get radiotap header */
    radiotap_header = (struct ieee80211_radiotap_header *)cursor;
    cursor += le16toh(radiotap_header->length); /* variable length */

    /* check size */
    safe_size = (cursor - packet) + sizeof(struct ieee80211_mac_header);
    if (packet_header->caplen < safe_size) {
        log_ts("Skipping too short packet %u bytes", packet_header->caplen);
        return;
    }

    /* get mac header */
    mac_header = (struct ieee80211_mac_header *)cursor;
    cursor += sizeof(struct ieee80211_mac_header) +
              (cursor[0] == ZZ_FCF_QOS_DATA ? 2 : 0); /* 2 bytes more for QoS */

    /* possible beacon frame */
    is_beacon = 0;
    if (!mac_header->from_ds && !mac_header->to_ds) {
        /* check if beacon */
        if (((uint8_t *)mac_header)[0] != ZZ_FCF_BEACON) {
            return;
        }

        is_beacon = 1;
        destination = zz_mac_addr_from_array(mac_header->address_1);
        source = zz_mac_addr_from_array(mac_header->address_2);
        bssid = zz_mac_addr_from_array(mac_header->address_3);
        station = 0; /* n.a. */
    }
    /* access point to station */
    else if (mac_header->from_ds && !mac_header->to_ds) {
        destination = zz_mac_addr_from_array(mac_header->address_1);
        bssid = zz_mac_addr_from_array(mac_header->address_2);
        source = zz_mac_addr_from_array(mac_header->address_3);
        station = destination;
    }
    /* station to access point */
    else if (mac_header->to_ds && !mac_header->from_ds){
        bssid = zz_mac_addr_from_array(mac_header->address_1);
        source = zz_mac_addr_from_array(mac_header->address_2);
        destination = zz_mac_addr_from_array(mac_header->address_3);
        station = source;
    } else {
        log_ts("Skipping packet due to frame direction");
        return;
    }

    /* prepare address representations */
    zz_mac_addr_sprint(bssid_str, bssid);
    zz_mac_addr_sprint(source_str, source);
    zz_mac_addr_sprint(destination_str, destination);
    zz_mac_addr_sprint(station_str, station);

    /* lookup or create a descriptor for this bss */
    if (zz_bsss_lookup(&zz->bsss, bssid, &bss)) {
        /* allowed if no constraints are specified or explicitly added */
        bss->is_allowed = (zz_members_is_empty(&zz->setup.allowed_bssids) ||
                           zz_members_match(&zz->setup.allowed_bssids, bssid));
    }

    /* skip unwanted access points */
    if (!bss->is_allowed) {
        #ifdef DEBUG
        if (!is_beacon) {
            log_ts("%s @ %s $'%s' - Skipping unwanted BSS traffic", station_str, bssid_str, bss->ssid);
        }
        #endif
        return;
    }

    /* save a beacon (just once per bss) */
    if (is_beacon) {
        if (!bss->has_beacon) {
            int ssid_length;
            const char *ssid;

            /* dump the packet if requested */
            if (zz->dumper) {
                pcap_dump((u_char *)zz->dumper, packet_header, packet);
            }

            /* fetch and save the ssid */
            get_ssid(cursor + ZZ_BEACON_SSID_PARAMS_OFFSET,
                     packet_header->caplen - (cursor - packet),
                     &ssid, &ssid_length);
            memcpy(bss->ssid, ssid, ssid_length);
            bss->has_beacon = 1;

            /* notify the user */
            zz_ssid_escape_sprint(bss->ssid, ssid, ssid_length);
            zz_out("BSS discovered %s $'%s'", bssid_str, bss->ssid);
        }

        /* anyway beacon processing stops here */
        return;
    }

    /* skip blacklisted stations */
    if (zz_members_match(&zz->setup.banned_stations, station)) {
        log_ts("%s @ %s $'%s' - Skipping banned station", station_str, bssid_str, bss->ssid);
        return;
    }

    /* detect broad/multicast traffic */
    if (destination == ZZ_MAC_ADDR_BCAST ||
        destination & ZZ_MAC_ADDR_MCAST_MASK) {

        /* for "handshaked" networks only, if explicitly requested */
        if (zz->setup.dump_group_traffic && bss->n_handshakes > 0) {
            bss->n_data_packets++;

            if (zz->dumper) {
                pcap_dump((u_char *)zz->dumper, packet_header, packet);
            }
        }

        return; /* anyway the processing stops here */
    }

    /* get llc+snap header (required by eapol) */
    llc_snap_header = (struct ieee8022_llc_snap_header *)cursor;
    cursor += sizeof(struct ieee8022_llc_snap_header);

    /* check actual snap and eapol presence */
    safe_size = (cursor - packet) + sizeof(struct ieee8021x_authentication_header);
    is_eapol = (packet_header->caplen >= safe_size &&
                llc_snap_header->dsap == ZZ_DSAP_SNAP &&
                llc_snap_header->ssap == ZZ_SSAP_SNAP &&
                llc_snap_header->control == ZZ_CONTROL_SNAP &&
                llc_snap_header->type == htobe16(ZZ_EAPOL_ETHERTYPE));

    /* get eapol header (if any) */
    if (is_eapol) {
        authentication_header = (struct ieee8021x_authentication_header *)cursor;
    } else {
        authentication_header = NULL;
    }

    /* advance the state machine and perform the needed actions */
    outcome = zz_process_packet(zz, station, bssid, packet_header,
                                authentication_header);

    if (outcome.ignore) {
        switch (outcome.ignore_reason) {
        case ZZ_IGNORE_REASON_RETRANSMISSION:
            log_ts("%s @ %s $'%s' - Handshake message #%d (retransmission)",
                   station_str, bssid_str, bss->ssid, outcome.handshake_info);
            break;
        case ZZ_IGNORE_REASON_INVALID_EAPOL:
            log_ts("%s @ %s $'%s' - Ignoring invalid key flags",
                   station_str, bssid_str, bss->ssid);
            break;
        case ZZ_IGNORE_REASON_INVALID_COUNTER:
            log_ts("%s @ %s $'%s' - Ignoring invalid replay counter",
                   station_str, bssid_str, bss->ssid);
            break;
        }

        return;
    }

    if (outcome.dump_packet) {
        if (!authentication_header) {
            bss->n_data_packets++;
        }
        if (zz->dumper) {
            pcap_dump((u_char *)zz->dumper, packet_header, packet);
        }
    }

    if (outcome.new_client || outcome.track_client) {
        if (zz->setup.is_live) {
            /* (re)start deauthenticating this client */
            zz_killer_post_message(&zz->killer, station, bssid, outcome);
        }
    }

    extra_info = "";
    if (outcome.track_client) {
        switch (outcome.track_reason) {
        case ZZ_TRACK_REASON_ALIVE:
            log_ts("%s @ %s $'%s' - Activity detected again",
                   station_str, bssid_str, bss->ssid);
            break;
        case ZZ_TRACK_REASON_FIRST_HANDSHAKE:
            extra_info = " (first attempt detected)";
            break;
        case ZZ_TRACK_REASON_EXPIRATION:
            extra_info = " (causes restart due to expiration)";
            break;
        case ZZ_TRACK_REASON_INVALIDATION:
            extra_info = " (caused restart due to invalidation)";
            break;
        }
    }

    if (outcome.handshake_info) {
        log_ts("%s @ %s $'%s' - Handshake message #%d%s",
               station_str, bssid_str, bss->ssid, outcome.handshake_info, extra_info);
    }

    if (outcome.new_client) {
        zz_out("New client %s @ %s $'%s'", station_str, bssid_str, bss->ssid);
    }

    if (outcome.got_handshake) {
        zz_out("^_^ Full handshake for %s @ %s $'%s'", station_str, bssid_str, bss->ssid);

        /* stop deauthenticating this client */
        if (zz->setup.is_live) {
            zz_killer_post_message(&zz->killer, station, bssid, outcome);
        }

        /* update stats */
        bss->n_handshakes++;
        zz_members_put(&bss->stations, station);
    }
}
