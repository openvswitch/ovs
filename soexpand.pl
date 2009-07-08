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
