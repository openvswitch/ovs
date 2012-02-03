# -*- perl -*-

# Picks a random TCP port and attempts to bind it, retrying a few
# times if the chosen port is in use.  This is better than just
# picking a random number without checking whether it is in use (but
# of course a race window still exists).
#
# On success, prints a port number on stdout and exits with status 0.
# On failure, prints an error on stderr and exits with a nonzero status.

use warnings;
use strict;
use Socket;

socket(SOCK, PF_INET, SOCK_STREAM, 0) || die "socket: $!\n";
for (my ($i) = 0; ; $i++) {
    my ($port) = int(rand(16383)) + 49152;
    if (bind(SOCK, sockaddr_in($port, INADDR_ANY))) {
        print "$port\n";
        exit 0;
    } elsif ($i < 10 && $!{EADDRINUSE}) {
        # Address already in use.  Try again.
    } else {
        die "bind: $!\n";
    }
}
