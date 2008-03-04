#! /usr/bin/perl

use warnings;
use strict;

if (@ARGV != 1) {
    print "usage: $0 input.pcap > output.h\n";
    print "where input.pcap is a packet capture in pcap format\n";
    print "and output.c is a C header file containing the packets\n";
    exit(1);
}
my ($in_file_name) = $ARGV[0];
open(INPUT, '<', $in_file_name) or die "$in_file_name: open: $!\n";

my ($file_header);
if (read(INPUT, $file_header, 24) != 24) {
    die "$in_file_name: could not read pcap header\n";
}

my ($s, $l);
if (substr($file_header, 0, 4) eq pack('V', 0xa1b2c3d4)) {
    ($s, $l) = ('v', 'V');
} elsif (substr($file_header, 0, 4) eq pack('N', 0xa1b2c3d4)) {
    ($s, $l) = ('n', 'N');
} else {
    die "$in_file_name: not a pcap file\n";
}

print <<'EOF';
#ifndef DP_TEST_PACKETS_H
#define DP_TEST_PACKETS_H 1

struct pkt {
	unsigned char *data;
	unsigned int len;
};
EOF

my ($n_packets) = 0;
for (;;) {
    my ($pkt_hdr) = must_read(16);
    last if $pkt_hdr eq '';

    my ($ts_sec, $ts_usec, $incl_len, $orig_len) = unpack("${l}4", $pkt_hdr);
    print STDERR "warning: captured less than len %u\n"
      if $incl_len < $orig_len;

    my ($pkt) = must_read($incl_len);
    die "$in_file_name: unexpected end of file\n" if !$pkt;

    print "\nstatic unsigned char p${n_packets}[] = {";
    my ($line_bytes) = 0;
    for my $c (map(ord($_), split(//, $pkt))) {
        if ($line_bytes++ % 13 == 0) {
            print "\n";
        }
        printf " 0x%02x,", $c;
    }
    print "\n};\n";
    $n_packets++;
}

print "\nstatic int num_packets = $n_packets;\n";
print "\nstatic struct pkt packets[] = {\n";
for my $i (0..$n_packets - 1) {
    print "  { p$i, sizeof p$i },\n";
}
print "};\n";

print "\n#endif\n";

sub must_read {
    my ($rq_bytes) = @_;
    my ($data);
    my ($nbytes) = read(INPUT, $data, $rq_bytes);
    die "$in_file_name: read: $!\n" if !defined $nbytes;
    die "$in_file_name: unexpected end of file\n"
      if $nbytes && $nbytes != $rq_bytes;
    return $data;
}
