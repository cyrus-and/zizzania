#!/bin/bash
USAGE='Usage: monitor.sh'
trap 'echo "$USAGE"; exit 1' ERR

DEVICE=${DEVICE:-wlan0}
CHANNEL=$1
ip link set $DEVICE down
iw dev $DEVICE set type monitor
ip link set $DEVICE up
