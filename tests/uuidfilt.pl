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

sub sort_set {
    my ($s) = @_;
    my (@uuids) = sort { $a <=> $b } (grep(/\d+/, split(/(\d+)/, $s)));
    return '["set",[' . join(',', map('["uuid","<' . $_ . '>"]', @uuids)) . ']]';
}

my $u = '[0-9a-fA-F]';
my $uuid_re = "${u}{8}-${u}{4}-${u}{4}-${u}{4}-${u}{12}";
while (<>) {
    s/($uuid_re)/lookup_uuid($1)/eg;

    # Sort sets like this:
    #    [["uuid","<1>"],["uuid","<0>"]]
    # to look like this:
    #    [["uuid","<0>"],["uuid","<1>"]]
    s/(\["set",\[(,?\["uuid","<\d+>"\])+\]\])/sort_set($1)/ge;
    print $_;
}
