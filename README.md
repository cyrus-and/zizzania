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

    sudo apt-get install libpcap-dev libglib2.0-dev

Build and install
-----------------

    make

The install process is not mandatory, zizzania can be run from this
directory. Just in case:

    sudo make install
    sudo make uninstall

Sample usage
------------

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
