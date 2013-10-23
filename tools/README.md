Tools
=====

This directory contains a set of useful scripts for managing wireless
devices. They require `ip` and `iw` executables and must be run as root
user. The default device is `wlan0`, this can be changed by setting the `DEVICE`
environment variable, for example:

    export DEVICE=eth0

Note that these tools are installed system wide with `sudo make install`.

zz-scan
-------

    zz-scan

List all the APs that are in range of the device. Requires managed mode.

zz-monitor
----------

    zz-monitor [channel]

Set the operating mode of the device to RFMON (required by zizzania). If
specified, also set the operating channel.

zz-managed
----------

    zz-managed

Set the operating mode of the device back to managed.

zz-channel
----------

    zz-channel channel

Set the operating channel of the device to `channel`.

zz-channel-hop
--------------

    zz-channel-hop timeout channel...

Hop from one channel to another in a round-robin fashion every `timeout`
seconds.
