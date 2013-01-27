zizzania - Automatic DeAuth attack
==================================

zizzania reads packets from a pcap file or from a wireless device (RFMON mode)
and recognizes the WPA 4-way handshakes of the clients. Captured traffic can be
saved to a pcap file that will contain, for each client, the handshake followed
by its data (IEEE 802.11 unicast data frames only): ready for subsequent
decryption. When capturing from a device, zizzania keeps on deauthenticating the
clients it finds until their handshakes are not gathered.

Dependencies
------------

    libpcap-dev (>= 1.1.1)
    libglib2.0-dev (>= 2.24.2)

Install
-------

    make
    sudo make install

Uninstall
---------

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
