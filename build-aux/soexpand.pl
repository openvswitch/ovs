# Copyright (c) 2008 Nicira, Inc.
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

my ($exit_code) = 0;
my (@include_dirs);
Getopt::Long::Configure ("bundling");
GetOptions("I|include=s" => \@include_dirs) or exit(1);
@include_dirs = ('.') if !@include_dirs;
OUTER: while (<STDIN>) {
    if (my ($name) = /^\.so (\S+)$/) {
	foreach my $dir (@include_dirs, '.') {
	    if (open(INNER, "$dir/$name")) {
		while (<INNER>) {
		    print $_;
		}
		close(INNER);
		next OUTER;
	    }
	}
	print STDERR "$name not found in: ", join(' ', @include_dirs), "\n";
	$exit_code = 1;
    }
    print $_;
}
exit $exit_code;
