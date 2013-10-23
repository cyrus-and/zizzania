Tools
=====

This directory contains a set of useful scripts for managing wireless
devices. They require `ip` and `iw` executables and must be run as root
user. The default device is `wlan0`, this can be changed by setting the `DEVICE`
environment variable, for example:

    export DEVICE=eth0

scan.sh
-------

    scan.sh

List all the APs that are in range of the device. Requires managed mode.

monitor.sh
----------

    monitor.sh [channel]

Set the operating mode of the device to RFMON (required by zizzania). If
specified, also set the operating channel.

managed.sh
----------

    managed.sh

Set the operating mode of the device back to managed.

channel.sh
----------

    channel.sh channel

Set the operating channel of the device to `channel`.

channel-hop.sh
--------------

    channel-hop.sh timeout channel...

Hop from one channel to another in a round-robin fashion every `timeout`
seconds.
