Tools
=====

This directory contains a set of useful scripts for managing wireless
devices. They require `ip` and `iw` executables and must be run as root user.

scan.sh
-------

    scan.sh device

List all the APs that are in range of `device`. Requires managed mode.

monitor.sh
----------

    monitor.sh device

Set the operating mode of `device` to RFMON (required by zizzania).

managed.sh
----------

    managed.sh device

Set the operating mode of `device` back to managed.

channel.sh
----------

    channel.sh device channel

Set the operating channel of `device` to `channel`.

channel-hop.sh
--------------

    channel-hop.sh device timeout channel...

Hop from one channel to another in a round-robin fashion every `timeout`
seconds.
