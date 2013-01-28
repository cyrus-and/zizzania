#!/bin/bash
USAGE='Usage: channel-hop.sh device timeout channel...'
trap 'echo "$USAGE"; exit 1' ERR

DEV=$1
TIMEOUT=$2
shift 2
while true ; do
    for CHANNEL in $@ ; do
        iw dev $DEV set channel $CHANNEL
        echo "Channel $CHANNEL"
        sleep $TIMEOUT
    done
done
