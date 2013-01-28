#!/bin/bash
USAGE='Usage: monitor.sh device'
trap 'echo "$USAGE"; exit 1' ERR

DEV=$1
ip link set $DEV down
iw dev $DEV set type monitor
ip link set $DEV up
