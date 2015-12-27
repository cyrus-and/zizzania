#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "ieee802.h"

static const char *hex_table[] = {
    "00", "01", "02", "03", "04", "05", "06", "07",
    "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27",
    "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37",
    "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57",
    "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67",
    "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77",
    "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87",
    "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97",
    "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
    "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
    "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"
};

zz_mac_addr zz_mac_addr_from_array(const uint8_t *octets) {
    return ((zz_mac_addr)octets[0] << 40) |
           ((zz_mac_addr)octets[1] << 32) |
           ((zz_mac_addr)octets[2] << 24) |
           ((zz_mac_addr)octets[3] << 16) |
           ((zz_mac_addr)octets[4] <<  8) |
           ((zz_mac_addr)octets[5] <<  0);
}

void zz_mac_addr_to_array(uint8_t *octets, zz_mac_addr addr) {
    octets[0] = (addr >> 40) & 0xff;
    octets[1] = (addr >> 32) & 0xff;
    octets[2] = (addr >> 24) & 0xff;
    octets[3] = (addr >> 16) & 0xff;
    octets[4] = (addr >>  8) & 0xff;
    octets[5] = (addr >>  0) & 0xff;
}

void zz_mac_addr_sprint(char *buffer, zz_mac_addr addr) {
    buffer[ 0] = hex_table[(addr >> 40) & 0xff][0];
    buffer[ 1] = hex_table[(addr >> 40) & 0xff][1];
    buffer[ 2] = ':';
    buffer[ 3] = hex_table[(addr >> 32) & 0xff][0];
    buffer[ 4] = hex_table[(addr >> 32) & 0xff][1];
    buffer[ 5] = ':';
    buffer[ 6] = hex_table[(addr >> 24) & 0xff][0];
    buffer[ 7] = hex_table[(addr >> 24) & 0xff][1];
    buffer[ 8] = ':';
    buffer[ 9] = hex_table[(addr >> 16) & 0xff][0];
    buffer[10] = hex_table[(addr >> 16) & 0xff][1];
    buffer[11] = ':';
    buffer[12] = hex_table[(addr >>  8) & 0xff][0];
    buffer[13] = hex_table[(addr >>  8) & 0xff][1];
    buffer[14] = ':';
    buffer[15] = hex_table[(addr >>  0) & 0xff][0];
    buffer[16] = hex_table[(addr >>  0) & 0xff][1];
    buffer[17] = '\0';
}

int zz_mac_addr_sscan(zz_mac_addr *addr, const char *buffer) {
    const char *ptr;
    int i;
    uint8_t octets[6] = {0};

    i = 0;
    ptr = buffer;
    while (i < 6) {
        char *chk;

        /* trigrams */
        switch ((ptr - buffer) % 3) {
        case 0:
        case 1:
            /* the first two are hex digits */
            if (!isxdigit(*ptr)) {
                return 0;
            }
            break;

        case 2:
            /* check proper terminator */
            octets[i++] = strtol(ptr - 2, &chk, 16);
            if (chk != ptr ||
                (i < 6 && *ptr != ':' && *ptr != '-') ||
                (i == 6 && *ptr != '\0')) {
                return 0;
            }
            break;
        }

        ptr++;
    }

    *addr = zz_mac_addr_from_array(octets);
    return 1;
}
