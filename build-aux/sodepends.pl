# Copyright (c) 2008, 2011 Nicira, Inc.
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
use Getopt::Long;

our ($exit_code) = 0;

our (@include_dirs);
Getopt::Long::Configure ("bundling");
GetOptions("I|include=s" => \@include_dirs) or exit(1);
@include_dirs = ('.') if !@include_dirs;

sub find_file {
    my ($name) = @_;
    foreach my $dir (@include_dirs, '.') {
        my $file = "$dir/$name";
        if (stat($file)) {
            return $file;
        }
    }
    print STDERR "$name not found in: ", join(' ', @include_dirs), "\n";
    $exit_code = 1;
    return;
}

print "# Generated automatically -- do not modify!    -*- buffer-read-only: t -*-\n";
for my $toplevel (sort(@ARGV)) {
    # Skip names that don't end in .in.
    next if $toplevel !~ /\.in$/;

    # Open file.
    my ($fn) = find_file($toplevel);
    next if !defined($fn);
    if (!open(OUTER, '<', $fn)) {
        print "$fn: open: $!\n";
        $exit_code = 1;
        next;
    }

    my (@dependencies);
  OUTER:
    while (<OUTER>) {
        if (my ($name) = /^\.so (\S+)$/) {
            push(@dependencies, $name) if find_file($name);
        }
    }
    close(OUTER);

    my ($output) = $toplevel;
    $output =~ s/\.in//;

    print "\n$output:";
    print " \\\n\t$_" foreach $toplevel, sort(@dependencies);
    print "\n";
    print "$_:\n" foreach $toplevel, sort(@dependencies);
}
exit $exit_code;
