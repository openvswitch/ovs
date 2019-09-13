# OpenVSwitch with wolfSSL

Below describes the steps for building OpenVSwitch with wolfSSL.

## wolfSSL

Support for OpenVSwitch added in: https://github.com/wolfSSL/wolfssl/pull/2399

```sh
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-opensslall --enable-keygen --enable-rsapss --enable-aesccm \
    --enable-aesctr --enable-des3 --enable-camellia --enable-curve25519 --enable-ed25519 \
    --enable-sessioncerts \
    CFLAGS="-DWOLFSSL_PUBLIC_MP -DWOLFSSL_DES_ECB"
make
make check
sudo make install
```

## Strongswan

```sh
sudo apt-get install flex bison byacc libsoup2.4-dev gperf

git clone https://github.com/strongswan/strongswan.git
cd strongswan
./autogen.sh #if packages are missing autogen.sh must be re-run
./configure --disable-defaults --enable-pki --enable-wolfssl --enable-pem
make
make check
sudo make install
```

If getting `proposal_keywords_static` error run:

```
cd src/libstrongswan
sed \
    -e "s:\@GPERF_LEN_TYPE\@:unsigned:" \
    crypto/proposal/proposal_keywords_static.h.in > crypto/proposal/proposal_keywords_static.h
cd ../..
```

### Strongswan Test Results

```
make check
...
Passed all 34 'libstrongswan' suites
PASS: libstrongswan_tests
=============
1 test passed
=============
```


## OpenVSwitch (OVS)

```sh
git clone https://github.com/openvswitch/ovs.git
cd ovs
git checkout wolf

./boot.sh
./configure --with-wolfssl
make
make check
sudo make install
```

Note: Contribution PR for OVS with wolfSSL is here: https://github.com/dgarske/ovs/tree/wolf

### OVS Test Results

Test instructions:
http://docs.openvswitch.org/en/latest/topics/testing/

```
make check
...
2408 tests were successful.
383 tests were skipped.
```


## Support

For questions or issue please email support@wolfssl.com
