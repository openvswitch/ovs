
OpenVSwitch with wolfSSL
========================

Below describes the steps for building OpenVSwitch with wolfSSL.

wolfSSL
-------

Support for OpenVSwitch added in: https://github.com/wolfSSL/wolfssl/pull/2399

.. code-block:: sh

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

OpenVSwitch (OVS)
-----------------

.. code-block:: sh

   git clone https://github.com/openvswitch/ovs.git
   cd ovs
   git checkout wolf

   ./boot.sh
   ./configure --with-wolfssl
   make
   make check
   sudo make install

Note: Contribution PR for OVS with wolfSSL is here: https://github.com/dgarske/ovs/tree/wolf

OVS Test Results
^^^^^^^^^^^^^^^^

Test instructions:
http://docs.openvswitch.org/en/latest/topics/testing/

.. code-block::

   make check
   ...
   2408 tests were successful.
   383 tests were skipped.

Support
-------

For questions or issue please email support@wolfssl.com
