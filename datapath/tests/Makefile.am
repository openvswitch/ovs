noinst_HEADERS = forward_t.h

forward_t.h: gen_forward_t.pl example.pcap
	perl $(srcdir)/gen_forward_t.pl $(srcdir)/example.pcap > forward_t.h.tmp
	mv forward_t.h.tmp forward_t.h

EXTRA_DIST = gen_forward_t.pl example.pcap
