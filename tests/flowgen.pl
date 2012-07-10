#! /usr/bin/perl

# Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use warnings;

open(FLOWS, ">&=3");# or die "failed to open fd 3 for writing: $!\n";
open(PACKETS, ">&=4");# or die "failed to open fd 4 for writing: $!\n";

# Print pcap file header.
print PACKETS pack('NnnNNNN',
                   0xa1b2c3d4,  # magic number
                   2,           # major version
                   4,           # minor version
                   0,           # time zone offset
                   0,           # time stamp accuracy
                   1518,        # snaplen
                   1);          # Ethernet

output(DL_HEADER => '802.2');

for my $dl_header (qw(802.2+SNAP Ethernet)) {
    my %a = (DL_HEADER => $dl_header);
    for my $dl_vlan (qw(none zero nonzero)) {
        my %b = (%a, DL_VLAN => $dl_vlan);

        # Non-IP case.
        output(%b, DL_TYPE => 'non-ip');

        for my $ip_options (qw(no yes)) {
            my %c = (%b, DL_TYPE => 'ip', IP_OPTIONS => $ip_options);
            for my $ip_fragment (qw(no first middle last)) {
                my %d = (%c, IP_FRAGMENT => $ip_fragment);
                for my $tp_proto (qw(TCP TCP+options UDP ICMP other)) {
                    output(%d, TP_PROTO => $tp_proto);
                }
            }
        }
    }
}

sub output {
    my (%attrs) = @_;

    # Compose flow.
    my (%flow);
    $flow{DL_SRC} = "00:02:e3:0f:80:a4";
    $flow{DL_DST} = "00:1a:92:40:ac:05";
    $flow{NW_PROTO} = 0;
    $flow{NW_TOS} = 0;
    $flow{NW_SRC} = '0.0.0.0';
    $flow{NW_DST} = '0.0.0.0';
    $flow{TP_SRC} = 0;
    $flow{TP_DST} = 0;
    if (defined($attrs{DL_VLAN})) {
        my (%vlan_map) = ('none' => 0xffff,
                          'zero' => 0,
                          'nonzero' => 0x0123);
        $flow{DL_VLAN} = $vlan_map{$attrs{DL_VLAN}};
    } else {
        $flow{DL_VLAN} = 0xffff; # OFP_VLAN_NONE
    }
    if ($attrs{DL_HEADER} eq '802.2') {
        $flow{DL_TYPE} = 0x5ff; # OFP_DL_TYPE_NOT_ETH_TYPE
    } elsif ($attrs{DL_TYPE} eq 'ip') {
        $flow{DL_TYPE} = 0x0800; # ETH_TYPE_IP
        $flow{NW_SRC} = '10.0.2.15';
        $flow{NW_DST} = '192.168.1.20';
        $flow{NW_TOS} = 44;
        if ($attrs{TP_PROTO} eq 'other') {
            $flow{NW_PROTO} = 42;
        } elsif ($attrs{TP_PROTO} eq 'TCP' ||
                 $attrs{TP_PROTO} eq 'TCP+options') {
            $flow{NW_PROTO} = 6; # IPPROTO_TCP
            $flow{TP_SRC} = 6667;
            $flow{TP_DST} = 9998;
        } elsif ($attrs{TP_PROTO} eq 'UDP') {
            $flow{NW_PROTO} = 17; # IPPROTO_UDP
            $flow{TP_SRC} = 1112;
            $flow{TP_DST} = 2223;
        } elsif ($attrs{TP_PROTO} eq 'ICMP') {
            $flow{NW_PROTO} = 1; # IPPROTO_ICMP
            $flow{TP_SRC} = 8;   # echo request
            $flow{TP_DST} = 0;   # code
        } else {
            die;
        }
        if ($attrs{IP_FRAGMENT} ne 'no' && $attrs{IP_FRAGMENT} ne 'first') {
            $flow{TP_SRC} = $flow{TP_DST} = 0;
        }
    } elsif ($attrs{DL_TYPE} eq 'non-ip') {
        $flow{DL_TYPE} = 0x5678;
    } else {
        die;
    }

    # Compose packet.
    my $packet = '';
    my $wildcards = 0;
    $packet .= pack_ethaddr($flow{DL_DST});
    $packet .= pack_ethaddr($flow{DL_SRC});
    if ($flow{DL_VLAN} != 0xffff) {
        $packet .= pack('nn', 0x8100, $flow{DL_VLAN});
    } else {
        $wildcards |= 1 << 20;   # OFPFW10_DL_VLAN_PCP
    }
    my $len_ofs = length($packet);
    $packet .= pack('n', 0) if $attrs{DL_HEADER} =~ /^802.2/;
    if ($attrs{DL_HEADER} eq '802.2') {
        $packet .= pack('CCC', 0x42, 0x42, 0x03); # LLC for 802.1D STP.
    } else {
        if ($attrs{DL_HEADER} eq '802.2+SNAP') {
            $packet .= pack('CCC', 0xaa, 0xaa, 0x03); # LLC for SNAP.
            $packet .= pack('CCC', 0, 0, 0);          # SNAP OUI.
        }
        $packet .= pack('n', $flow{DL_TYPE});
        if ($attrs{DL_TYPE} eq 'ip') {
            my $ip = pack('CCnnnCCnNN',
                          (4 << 4) | 5,    # version, hdrlen
                          $flow{NW_TOS},   # type of service
                          0,               # total length (filled in later)
                          65432,           # id
                          0,               # frag offset
                          64,              # ttl
                          $flow{NW_PROTO}, # protocol
                          0,               # checksum
                          0x0a00020f,      # source
                          0xc0a80114);     # dest
            if ($attrs{IP_OPTIONS} eq 'yes') {
                substr($ip, 0, 1) = pack('C', (4 << 4) | 8);
                $ip .= pack('CCnnnCCCx',
                            130,       # type
                            11,        # length
                            0x6bc5,    # top secret
                            0xabcd,
                            0x1234,
                            1,
                            2,
                            3);
            }
            if ($attrs{IP_FRAGMENT} ne 'no') {
                my (%frag_map) = ('first' => 0x2000, # more frags, ofs 0
                                  'middle' => 0x2111, # more frags, ofs 0x888
                                  'last' => 0x0222); # last frag, ofs 0x1110
                substr($ip, 6, 2)
                  = pack('n', $frag_map{$attrs{IP_FRAGMENT}});
            }

            if ($attrs{TP_PROTO} =~ '^TCP') {
                my $tcp = pack('nnNNnnnn',
                               $flow{TP_SRC},     # source port
                               $flow{TP_DST},     # dest port
                               87123455,          # seqno
                               712378912,         # ackno
                               (5 << 12) | 0x02 | 0x10, # hdrlen, SYN, ACK
                               5823,                    # window size
                               18923,                   # checksum
                               12893); # urgent pointer
                if ($attrs{TP_PROTO} eq 'TCP+options') {
                    substr($tcp, 12, 2) = pack('n', (6 << 12) | 0x02 | 0x10);
                    $tcp .= pack('CCn', 2, 4, 1975); # MSS option
                }
                $tcp .= 'payload';
                $ip .= $tcp;
            } elsif ($attrs{TP_PROTO} eq 'UDP') {
                my $len = 15;
                my $udp = pack('nnnn', $flow{TP_SRC}, $flow{TP_DST}, $len, 0);
                $udp .= chr($len) while length($udp) < $len;
                $ip .= $udp;
            } elsif ($attrs{TP_PROTO} eq 'ICMP') {
                $ip .= pack('CCnnn',
                            8,        # echo request
                            0,        # code
                            0,        # checksum
                            736,      # identifier
                            931);     # sequence number
            } elsif ($attrs{TP_PROTO} eq 'other') {
                $ip .= 'other header';
            } else {
                die;
            }
            substr($ip, 2, 2) = pack('n', length($ip));
            $packet .= $ip;
        }
    }
    if ($attrs{DL_HEADER} =~ /^802.2/) {
        my $len = length ($packet);
        $len -= 4 if $flow{DL_VLAN} != 0xffff;
        substr($packet, $len_ofs, 2) = pack('n', $len);
    }

    print join(' ', map("$_=$attrs{$_}", keys(%attrs))), "\n";
    print join(' ', map("$_=$flow{$_}", keys(%flow))), "\n";
    print "\n";

    print FLOWS pack('Nn',
                     $wildcards, # wildcards
                     1);         # in_port
    print FLOWS pack_ethaddr($flow{DL_SRC});
    print FLOWS pack_ethaddr($flow{DL_DST});
    print FLOWS pack('nCxnCCxxNNnn',
                     $flow{DL_VLAN},
                     0,          # DL_VLAN_PCP
                     $flow{DL_TYPE},
                     $flow{NW_TOS},
                     $flow{NW_PROTO},
                     inet_aton($flow{NW_SRC}),
                     inet_aton($flow{NW_DST}),
                     $flow{TP_SRC},
                     $flow{TP_DST});

    print PACKETS pack('NNNN',
                       0,                # timestamp seconds
                       0,                # timestamp microseconds
                       length($packet),  # bytes saved
                       length($packet)), # total length
                  $packet;
}

sub pack_ethaddr {
    local ($_) = @_;
    my $xx = '([0-9a-fA-F][0-9a-fA-F])';
    my (@octets) = /$xx:$xx:$xx:$xx:$xx:$xx/;
    @octets == 6 or die $_;
    my ($out) = '';
    $out .= pack('C', hex($_)) foreach @octets;
    return $out;
}

sub inet_aton {
    local ($_) = @_;
    my ($a, $b, $c, $d) = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    defined $d or die $_;
    return ($a << 24) | ($b << 16) | ($c << 8) | $d;
}
