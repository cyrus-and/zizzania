#!/bin/bash
USAGE='Usage: scan.sh device'
trap 'echo "$USAGE"; exit 1' ERR

DEV=$1
iw dev $DEV scan | less
