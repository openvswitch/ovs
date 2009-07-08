#! /bin/sh -e
srcdir=`cd $srcdir && pwd`
trap 'rm -f flows$$ pcap$$ out$$' 0 1 2 13 15
cd tests
"$srcdir"/tests/flowgen.pl >/dev/null 3>flows$$ 4>pcap$$
./test-flows <flows$$ 3<pcap$$ >out$$ || true
diff -u - out$$ <<EOF
checked 247 packets, 0 errors
EOF
