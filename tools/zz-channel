#!/bin/bash
USAGE='Usage: channel.sh channel'
trap 'echo "$USAGE"; exit 1' ERR

DEVICE=${DEVICE:-wlan0}
CHANNEL=$1
iw dev $DEVICE set channel $CHANNEL
