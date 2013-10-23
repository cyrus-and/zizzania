#!/bin/bash
USAGE='Usage: managed.sh'
trap 'echo "$USAGE"; exit 1' ERR

DEVICE=${DEVICE:-wlan0}
ip link set $DEVICE down
iw dev $DEVICE set type managed
ip link set $DEVICE up
