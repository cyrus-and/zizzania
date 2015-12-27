zizzania - automated DeAuth attack
==================================

zizzania sniffs wireless traffic listening for WPA handshakes and dumping only
those frames suitable to be decrypted (one beacon + EAPOL frames + data). In
order to speed up the process, zizzania sends IEEE 802.11 DeAuth frames to the
stations whose handshake is needed, properly handling retransmissions and
reassociations and trying to limit the number of DeAuth frames sent to each
station.

Usage
-----

    zizzania (-r <file> | -i <device> [-c <channel>]
              ([-n] | [-d <count>] [-a <count>] [-t <seconds>]))
             [-b <address>...] [-x <address>...] [-2 | -3]
             [-w <file> [-g]] [-v]

    -i <device>   Use <device> for both capture and injection
    -c <channel>  Set <device> to RFMON mode on <channel>
    -n            Passively wait for WPA handshakes
    -d <count>    Send groups of <count> deauthentication frames
    -a <count>    Perform <count> deauthentications before giving up
    -t <seconds>  Time to wait between two deauthentication attempts
    -r <file>     Read packets from <file> (- for stdin)
    -b <address>  Limit the operations to the given BSSID
    -x <address>  Exclude the given station from the operations
    -2            Settle for the first two handshake messages
    -3            Settle for the first three handshake messages
    -w <file>     Write packets to <file> (- for stdout)
    -g            Also dump multicast and broadcast traffic
    -v            Print verbose messages to stderr (toggle with SIGUSR1)

Examples
--------

* Put the network interface in RFMON mode on channel 6 and save the traffic
  gathered from the stations of a specific access point:

      zizzania -i wlan0 -c 6 -b aa:bb:cc:dd:ee:ff -w out.pcap

* Passively analyze all the access points and the stations on the current
  channel assuming that the interface is already RFMON mode:

      zizzania -i wlan0 -n

* Strip unnecessary packets from a pcap but file excluding the traffic of one
  articular station and considering an handshake complete after just the first
  two messages (which should be enough for unicast traffic decryption):

      zizzania -r in.pcap -x aa:bb:cc:dd:ee:ff -w out.pcap

* Use [airdecap-ng][aircrack-ng] to decrypt a pcap file created by zizzania:

      airdecap-ng -b aa:bb:cc:dd:ee:ff -e SSID -p passphrase out.pcap

Dependencies
------------

* [SCons][scons]
* [libpcap][libpcap]
* [uthash][uthash]

### Debian-based

    sudo apt-get install scons libpcap-dev uthash-dev

### Mac OS X ([Homebrew](http://brew.sh/))

    brew install scons libpcap clib
    clib install troydhanson/uthash  # from this directory

Or as an alternative to [clib][clib] just throw [uthash.h][uthash.h] in any
valid headers search path.

Build
-----

    make

The install process is not mandatory, zizzania can be run from the `src`
directory. Just in case:

    sudo make install
    sudo make uninstall

Mac OS X support
----------------

In order to sniff packets live and to perform the deauthentication phase
zizzania requires that the chosen interface/driver supports RFMON mode with
injection capabilities. This is known to be troublesome with Mac OS X and hence
it is not possible out of the box with zizzania.

[aircrack-ng]: http://www.aircrack-ng.org/
[scons]: http://www.scons.org/
[libpcap]: http://www.tcpdump.org/
[uthash]: https://troydhanson.github.io/uthash/
[clib]: https://github.com/clibs/clib
[uthash.h]: https://raw.githubusercontent.com/troydhanson/uthash/master/src/uthash.h
