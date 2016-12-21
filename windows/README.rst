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

==============
Windows README
==============

This directory contains tooling to generate an MSI installer for Open vSwitch
on Windows, including CLI executables, services and the Hyper-V vswitch
forwarding extension.

Requirements
------------

* Visual Studio 2013

  Community, Professional, Premium or Ultimate editions can be used.

  Visual Studio Community 2013 is freely available from `visualstudio.com
  <https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx>`__

* WiX Toolset 3.9

  Download and install from `wixtoolset.org
  <http://wixtoolset.org/releases/v3.9/stable>`__

* ``Microsoft_VC120_CRT_x86.msm``

  This Windows merge module is available with Visual Studio and contains the
  Visual C++ 2013 x86 runtime redistributables files.  Copy the file in the
  ``Redist`` directory.

Open vSwitch installer
----------------------

The installer will be generated under the following path::

    windows\ovs-windows-installer\bin\Release\OpenvSwitch.msi

.. note::

  The kernel driver needs to be signed.

Build Instructions
------------------

Build the solution in the Visual Studio IDE or via command line::

    msbuild ovs-windows-installer.sln /p:Platform=x86 /p:Configuration=Release

Silent installation
-------------------

::

    msiexec /i OpenvSwitch.msi ADDLOCAL=OpenvSwitchCLI,OpenvSwitchDriver /l*v log.txt
