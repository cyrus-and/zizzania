#!/bin/bash
USAGE='Usage: managed.sh device'
trap 'echo "$USAGE"; exit 1' ERR

DEV=$1
ip link set $DEV down
iw dev $DEV set type managed
ip link set $DEV up
