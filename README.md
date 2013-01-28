zizzania - Automatic DeAuth attack
==================================

zizzania deauthenticates the clients of one or more access points until their
WPA handshakes are not taken, in doing so it tries to minimize multiple
deauthentications. It can also work passively.

The captured traffic can be saved to a pcap file that contains every handshake
found followed by the actual payload traffic (IEEE 802.11 unicast data frames
only). The WPA decryption phase is left to tools like Wireshark.

It can even strip unnecessary packets from an existing pcap file captured by a
wireless interface in RFMON mode.

Dependencies
------------

For Debian-based distros just run:

    sudo apt-get install cmake libpcap-dev libglib2.0-dev

Build and install
-----------------

    mkdir build
    cd build
    cmake ..
    make

The install process is not mandatory, zizzania can be run from the `build`
directory. Just in case:

    sudo make install
    sudo make uninstall

Sample usage
------------

Run zizzania without arguments to display a brief usage message:

    Usage:

        zizzania -i <device> | -r <file>
                 -b <bssid_1> -b <bssid_2> ... | -a
                 [-n] [-w <file>]

        -i <device> : use <device> for both capture and injection
        -r <file>   : read packets from <file> (- for stdin)
        -b <bssid>  : handshakes of <bssid> clients only
        -a          : auto discover BSSIDs
        -n          : passively look for handshakes
        -w          : dump captured packets to <file> (- for stdout)

Take a look around:

    sudo zizzania -i wlan0 -n -a

Passively wait for handshakes of a specific AP and dump decryptable traffic to a
file:

    sudo zizzania -i wlan0 -n -b 11:22:33:44:55:66 -w passive.cap

Force the reconnection of the clients of two specific APs and dump the
decryptable traffic to a gzipped file:

    sudo zizzania -i wlan0 \
                  -b 11:22:33:44:55:66 \
                  -b aa:bb:cc:dd:ee:ff -w - | gzip > active.cap.gz

Extract the decryptable traffic of a specific AP from a gzipped file and dump it
to a file:

    gunzip < file.cap.gz | zizzania -r - -b 11:22:33:44:55:66 -w crop.cap

Typical output
--------------

The generated output is meant to be easily parsable.

Every time zizzania sniffs a new client it dumps a line in the form:

    N 00:11:22:33:44:55 @ aa:bb:cc:dd:ee:ff

This means that there is some activity from the station with MAC address
`00:11:22:33:44:55` associated with the AP `aa:bb:cc:dd:ee:ff`.

Instead, each properly recognized handshake produces the following:

    H 00:11:22:33:44:55 @ aa:bb:cc:dd:ee:ff <<<

The `<<<` is there just for visual feedback.

Deauthentication loop
---------------------

When run in active mode (with `-i` and without `-n` options) zizzania
continuously looks for new clients and once in awhile sends deauthentication
frames to the clients for which it has not yet captured the handshake.
