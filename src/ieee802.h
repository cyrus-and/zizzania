#ifndef ZZ_IEEE_802_H
#define ZZ_IEEE_802_H

#include <stdint.h>

#include "endian.h"

#define ZZ_MAC_ADDR_STRING_SIZE 18

#define ZZ_MAC_ADDR_BCAST      0xffffffffffffULL
#define ZZ_MAC_ADDR_MCAST_MASK (1ULL << 40)

#define ZZ_FCF_BEACON           0x80
#define ZZ_FCF_DATA             0x08
#define ZZ_FCF_QOS_DATA         0x88
#define ZZ_FCF_DEAUTHENTICATION 0xc0

#define ZZ_DSAP_SNAP    0xaa
#define ZZ_SSAP_SNAP    0xaa
#define ZZ_CONTROL_SNAP 0x03

#define ZZ_BEACON_SSID_PARAMS_OFFSET 0x0c
#define ZZ_BEACON_SSID_PARAM_TYPE    0x00
#define ZZ_BEACON_MAX_SSID_LENGTH    0xff /* spec says 32 */
/* each character could possibly be escaped as \xHH */
#define ZZ_BEACON_MAX_SSID_ESCAPED_LENGTH  ZZ_BEACON_MAX_SSID_LENGTH * 4

#define ZZ_EAPOL_ETHERTYPE 0x888e /* network byte order */

#define ZZ_EAPOL_MASK_1  0x1fc8 /* 0b0001111111001000 */
#define ZZ_EAPOL_MASK_2  0x1fc8 /* 0b0001111111001000 */
#define ZZ_EAPOL_MASK_3  0x1f88 /* 0b0001111110001000 */
#define ZZ_EAPOL_MASK_4  0x1fc8 /* 0b0001111111001000 */

#define ZZ_EAPOL_FLAGS_1 0x0088 /* 0b0000000010001000 */
#define ZZ_EAPOL_FLAGS_2 0x0108 /* 0b0000000100001000 */
#define ZZ_EAPOL_FLAGS_3 0x1388 /* 0b0001001110001000 */
#define ZZ_EAPOL_FLAGS_4 0x0308 /* 0b0000001100001000 */

#define ZZ_DEAUTHENTICATION_SEQUENCE(x) (((x) & ((1 << 12) - 1)) << 4)
#define ZZ_DEAUTHENTICATION_REASON      0x07

typedef uint64_t zz_mac_addr;

struct ieee80211_radiotap_header { /* always little endian */
    uint8_t version;
    uint8_t padding;
    uint16_t length;
    uint32_t present;
}
__attribute__((__packed__));

struct ieee80211_mac_header { /* BPF wlan */
    /* frame control field (2byte) */
    uint8_t version:2;
    uint8_t type:2;
    uint8_t sub_type:4;
    uint8_t to_ds:1;
    uint8_t from_ds:1;
    uint8_t more_fragments:1;
    uint8_t retry:1;
    uint8_t power_management:1;
    uint8_t more_data:1;
    uint8_t wep:1;
    uint8_t order:1;

    uint16_t duration;
    uint8_t address_1[6];
    uint8_t address_2[6];
    uint8_t address_3[6];
    uint16_t sequence_control;
}
__attribute__((__packed__));

struct ieee8022_llc_snap_header {
    /* llc, should be 0xaa 0xaa 0x03 for snap */
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control;

    /* snap */
    uint8_t oui[3];
    uint16_t type; /* should be 0x888e for ieee8021x_authentication */
}
__attribute__((__packed__));

struct ieee8021x_authentication_header {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint8_t descriptor_type;
    uint16_t flags;
    uint16_t key_length;
    uint64_t replay_counter;
    uint8_t key_nonce[32];
    uint8_t key_iv[16];
    uint8_t key_rsc[8];
    uint8_t reserved[8];
    uint8_t key_mic[16];
    uint16_t key_data_length;
}
__attribute__((__packed__));

struct ieee80211_deauthentication_header {
    uint16_t reason;
}
__attribute__((__packed__));

zz_mac_addr zz_mac_addr_from_array(const uint8_t *array);
void zz_mac_addr_to_array(uint8_t *octets, zz_mac_addr addr);

void zz_mac_addr_sprint(char *buffer, zz_mac_addr addr);
int zz_mac_addr_sscan(zz_mac_addr *addr, const char *buffer, const char *terminators);

/* at least ZZ_BEACON_MAX_SSID_ESCAPE_LENGTH + 1 for '\0' */
void zz_ssid_escape_sprint(char *buffer, const char *ssid, int ssid_length);

#endif
