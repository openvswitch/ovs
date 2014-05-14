#! /usr/bin/perl

use strict;
use warnings;

# Breaks lines read from <STDIN> into groups using blank lines as
# group separators, then sorts lines within the groups for
# reproducibility.

sub compare_lines {
    my ($a, $b) = @_;

    my $u = '[0-9a-fA-F]';
    my $uuid_re = "${u}{8}-${u}{4}-${u}{4}-${u}{4}-${u}{12}";
    if ($a =~ /^$uuid_re/) {
        if ($b =~ /^$uuid_re/) {
            return substr($a, 36) cmp substr($b, 36);
        } else {
            return 1;
        }
    } elsif ($b =~ /^$uuid_re/) {
        return -1;
    } else {
        return $a cmp $b;
    }
}

sub output_group {
    my (@group) = @_;
    print "$_\n" foreach sort { compare_lines($a, $b) } @group;
}

if ("$^O" eq "msys") {
    $/ = "\r\n";
}
my @group = ();
while (<STDIN>) {
    chomp;
    if ($_ eq '') {
        output_group(@group);
        @group = ();
        print "\n";
    } else {
        if (/^,/ && @group) {
            $group[$#group] .= "\n" . $_;
        } else {
            push(@group, $_);
        }
    }
}

output_group(@group) if @group;
