#!/bin/bash
USAGE='Usage: channel.sh device channel'
trap 'echo "$USAGE"; exit 1' ERR

DEV=$1
CHANNEL=$2
iw dev $DEV set channel $CHANNEL
