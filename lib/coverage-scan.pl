# Copyright (c) 2009 Nicira Networks.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;

my %counters;
while (<>) {
    my ($counter) = /^\s*COVERAGE_(?:INC|ADD)\s*\(\s*([a-zA-Z_][a-zA-Z_0-9]*)/
      or next;
    push (@{$counters{$counter}}, "$ARGV:$.");
} continue {
    # This magic resets $. from one file to the next.  See "perldoc -f eof".
    close ARGV if eof;
}

print <<EOF;
#include "coverage-counters.h"
#include <stddef.h>
#include "coverage.h"
#include "util.h"

EOF

for my $counter (sort(keys(%counters))) {
    my $locations = join(', ', @{$counters{$counter}});
    print <<EOF;
/* $locations */
struct coverage_counter ${counter}_count = { "$counter", 0, 0 };

EOF
}
print "struct coverage_counter *coverage_counters[] = {\n";
print "    \&${_}_count,\n" foreach (sort(keys(%counters)));
print "};\n";
print "size_t coverage_n_counters = ARRAY_SIZE(coverage_counters);\n";
