#! /usr/bin/perl

use strict;
use warnings;

our %uuids;
our $n_uuids = 0;
sub lookup_uuid {
    my ($uuid) = @_;
    if (!exists($uuids{$uuid})) {
        $uuids{$uuid} = $n_uuids++;
    }
    return "<$uuids{$uuid}>";
}

my $u = '[0-9a-fA-F]';
my $uuid_re = "${u}{8}-${u}{4}-${u}{4}-${u}{4}-${u}{12}";
while (<>) {
    s/($uuid_re)/lookup_uuid($1)/eg;
    print $_;
}
