# -*- perl -*-

use strict;
use warnings;

if (@ARGV < 2) {
    print <<EOF;
$0: to check ODP sets of actions for equivalence
usage: $0 ACTIONS1 ACTIONS2 [NAME=NUMBER]...
where ACTIONS1 and ACTIONS2 are sets of ODP actions as output by, e.g.
      "ovs-dpctl dump-flows" and each NAME=NUMBER pair identifies an ODP
      port's name-to-number mapping.

Exits with status 0 if ACTIONS1 and ACTIONS2 are equivalent, with
status 1 if they differ.
EOF
    exit 1;
}

# Construct mappings between port numbers and names.
our (%name_to_number);
our (%number_to_name);
for (@ARGV[2..$#ARGV]) {
    my ($name, $number) = /([^=]+)=([0-9]+)/
      or die "$_: bad syntax (use --help for help)\n";
    $number_to_name{$number} = $name;
    $name_to_number{$name} = $number;
}

my $n1 = normalize_odp_actions($ARGV[0]);
my $n2 = normalize_odp_actions($ARGV[1]);
print "Normalized action set 1: $n1\n";
print "Normalized action set 2: $n2\n";
exit($n1 ne $n2);

sub normalize_odp_actions {
    my ($actions) = @_;

    # Transliterate all commas inside parentheses into semicolons.
    undef while $actions =~ s/(\([^),]*),([^)]*\))/$1;$2/g;

    # Split on commas.
    my (@actions) = split(',', $actions);

    # Map port numbers into port names.
    foreach my $s (@actions) {
        $s = $number_to_name{$s} if exists($number_to_name{$s});
    }

    # Sort sequential groups of port names into alphabetical order.
    for (my $i = 0; $i <= $#actions; ) {
        my $j = $i + 1;
        if (exists($name_to_number{$actions[$i]})) {
            for (; $j <= $#actions; $j++) {
                last if !exists($name_to_number{$actions[$j]});
            }
        }
        @actions[$i..($j - 1)] = sort(@actions[$i..($j - 1)]);
        $i = $j;
    }

    # Now compose a string again and transliterate semicolons back to commas.
    $actions = join(',', @actions);
    $actions =~ tr/;/,/;
    return $actions;
}
