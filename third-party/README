This directory contains third-party software that may be useful for
debugging.

tcpdump
-------
The "ofp-tcpdump.patch" patch adds the ability to parse OpenFlow
messages to tcpdump.  These instructions assume that tcpdump 4.3.0
is going to be used, but it should work with other versions that are not
substantially different.  To begin, download tcpdump and apply the
patch:

    wget http://www.tcpdump.org/release/tcpdump-4.3.0.tar.gz
    tar xzf tcpdump-4.3.0.tar.gz
    ln -s tcpdump-4.3.0 tcpdump
    patch -p0 < ofp-tcpdump.patch

Then build the new version of tcpdump:

    cd tcpdump
    ./configure
    make

Clearly, tcpdump can only parse unencrypted packets, so you will need to
connect the controller and datapath using plain TCP.  To look at the
traffic, tcpdump will be started in a manner similar to the following:

    sudo ./tcpdump -s0 -i eth0 port 6633

The "-s0" flag indicates that tcpdump should capture the entire packet.
If the OpenFlow message is not received in its entirety, "[|openflow]" will 
be printed instead of the OpenFlow message contents.

The verbosity of the output may be increased by adding additional "-v"
flags.  If "-vvv" is used, the raw OpenFlow data is also printed in
hex and ASCII.
