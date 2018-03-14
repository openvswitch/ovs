..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

======================
Open vSwitch on NetBSD
======================

On NetBSD, you might want to install requirements from pkgsrc.  In that case,
you need at least the following packages.

- automake
- libtool-base
- gmake
- python27
- py27-six
- py27-xml

Some components have additional requirements. Refer to :doc:`general` for more
information.

Assuming you are running NetBSD/amd64 6.1.2, you can download and install
pre-built binary packages as the following::

    $ PKG_PATH=http://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/7.0.2/All/
    $ export PKG_PATH
    $ pkg_add automake libtool-base gmake python27 py27-six py27-xml \
        pkg_alternatives

.. note::
  You might get some warnings about minor version mismatch. These can be safely
  ignored.

NetBSD's ``/usr/bin/make`` is not GNU make.  GNU make is installed as
``/usr/pkg/bin/gmake`` by the above mentioned ``gmake`` package.

As all executables installed with pkgsrc are placed in ``/usr/pkg/bin/``
directory, it might be a good idea to add it to your PATH. Or install OVS by
``gmake`` and ``gmake install``.

Open vSwitch on NetBSD is currently "userspace switch" implementation in the
sense described in :doc:`userspace` and :doc:`/topics/porting`.
