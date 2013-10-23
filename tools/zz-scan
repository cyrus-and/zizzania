#!/bin/bash
USAGE='Usage: scan.sh'
trap 'echo "$USAGE"; exit 1' ERR

DEVICE=${DEVICE:-wlan0}
iw dev $DEVICE scan 2>&1 | grep $'^BSS\|^\tsignal\|^\tSSID\|channel [0-9]\+' | less
