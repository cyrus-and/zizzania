#include "clients.h"
#include "handshake.h"
#include "ieee802.h"
#include "params.h"
#include "terminal.h"

#define abs(x, y) ((x) > (y) ? (x) - (y) : (y) - (x))
#define is_done(handshake, max) \
    ((((handshake) & ((1 << (max)) - 1)) == ((1 << (max)) - 1)))

zz_packet_outcome zz_process_packet(zz_handler *zz,
    zz_mac_addr station, zz_mac_addr bssid,
    const struct pcap_pkthdr *packet_header,
    const struct ieee8021x_authentication_header *auth) {
    zz_client *client;
    time_t last_data_ts;
    zz_packet_outcome outcome = {0};

    /* create or fetch the client descriptor */
    if (zz_clients_lookup(&zz->clients, station, bssid, &client)) {
        /* surely attempt to track the client if new */
        outcome.new_client = 1;
    }

    /* keep track of the last seen data packet */
    last_data_ts = client->last_data_ts;
    client->last_data_ts = packet_header->ts.tv_sec;

    /* this is an authentication message */
    if (auth) {
        unsigned handshake_id;
        uint64_t ts;
        uint64_t replay_counter_1; /* expected replay counter of the first */
        int initialize = 0;

        /* compute the timestamp */
        ts = (packet_header->ts.tv_sec * 1000000 +
              packet_header->ts.tv_usec % 1000000);

        /* try to guess the handshake number */
        if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_1) == ZZ_EAPOL_FLAGS_1) {
            handshake_id = 0;
            replay_counter_1 = be64toh(auth->replay_counter);
        } else if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_2) == ZZ_EAPOL_FLAGS_2) {
            handshake_id = 1;
            replay_counter_1 = be64toh(auth->replay_counter);
        } else if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_3) == ZZ_EAPOL_FLAGS_3) {
            handshake_id = 2;
            replay_counter_1 = be64toh(auth->replay_counter) - 1;
        } else if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_4) == ZZ_EAPOL_FLAGS_4) {
            handshake_id = 3;
            replay_counter_1 = be64toh(auth->replay_counter) - 1;
        } else {
            #ifdef DEBUG
            zz_log("Unrecognizable EAPOL flags 0x%04hx", be16toh(auth->flags));
            #endif
            outcome.ignore = 1;
            outcome.ignore_reason = ZZ_IGNORE_REASON_INVALID_EAPOL;
            return outcome;
        }
        outcome.handshake_info = handshake_id + 1;

        /* initialize after the first handshake message ever */
        if (!client->handshake) {
            initialize = 1;
            outcome.track_reason = ZZ_TRACK_REASON_FIRST_HANDSHAKE;
        }
        /* reinitialize after too much time passed since the last one (even if
         * this is a retransmission) */
        else if (abs(client->last_handshake_ts, ts) > ZZ_MAX_HANDSHAKE_TIME) {
            initialize = 1;
            outcome.track_reason = ZZ_TRACK_REASON_EXPIRATION;
        }
        /* if already received this message */
        else if (client->handshake & (1 << handshake_id)) {
            /* if this is a retransmission or the one saved was, ignore it */
            if (memcmp(&client->headers[handshake_id], auth,
                       sizeof(struct ieee8021x_authentication_header)) == 0) {
                outcome.ignore = 1;
                outcome.ignore_reason = ZZ_IGNORE_REASON_RETRANSMISSION;
                return outcome;
            }
            /* otherwise reinitialize */
            else {
                initialize = 1;
                outcome.track_reason = ZZ_TRACK_REASON_INVALIDATION;
            }
        }
        /* if first time received this message (handshake in progress) */
        else {
            int ok;

            /* check the replay counter */
            switch (handshake_id) {
            case 0: case 1:
                ok = (be64toh(auth->replay_counter) == client->replay_counter);
                break;
            case 2: case 3:
                ok = (be64toh(auth->replay_counter) == client->replay_counter + 1);
                break;
            }

            if (!ok) {
                outcome.ignore = 1;
                outcome.ignore_reason = ZZ_IGNORE_REASON_INVALID_COUNTER;
                return outcome;
            }

            /* store the message */
            client->handshake |= 1 << handshake_id;
            memcpy(&client->headers[handshake_id], auth,
                   sizeof(struct ieee8021x_authentication_header));

            /* if this is the last needed message */
            if (handshake_id < zz->setup.max_handshake &&
                is_done(client->handshake, zz->setup.max_handshake)) {
                outcome.got_handshake = 1;
            }
        }

        /* if (re)initialization has been triggered */
        if (initialize) {
            outcome.grace_time = 1; /* handshake detected */
            outcome.track_client = 1;
            client->last_handshake_ts = ts;
            client->replay_counter = replay_counter_1;
            client->handshake = 1 << handshake_id;
            memcpy(&client->headers[handshake_id], auth,
                   sizeof(struct ieee8021x_authentication_header));
        }
    }
    /* this is a data packet */
    else {
        /* notify if traffic is detected again after "long" time so if the killer
         * gave up it can restart the deauthentication process; the "long" time
         * is set to the killer "giveup time" */
        if (last_data_ts &&
            !is_done(client->handshake, zz->setup.max_handshake) &&
            (packet_header->ts.tv_sec - last_data_ts >
             (zz->setup.killer_max_attempts - 1) * zz->setup.killer_interval)) {
            outcome.track_client = 1;
            outcome.track_reason = ZZ_TRACK_REASON_ALIVE;
        }
    }

    /* dump valid eapol messages and data for completed (according to max) clients */
    if (auth || is_done(client->handshake, zz->setup.max_handshake)) {
        outcome.dump_packet = 1;
    }

    return outcome;
}
