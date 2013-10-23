#!/bin/bash
USAGE='Usage: channel-hop.sh timeout channel...'
trap 'echo "$USAGE"; exit 1' ERR

DEVICE=${DEVICE:-wlan0}
TIMEOUT=$1
shift 2
while true ; do
    for CHANNEL in $@ ; do
        iw dev $DEVICE set channel $CHANNEL
        echo "Channel $CHANNEL"
        sleep $TIMEOUT
    done
done
