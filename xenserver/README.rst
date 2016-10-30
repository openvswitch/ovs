..
      Copyright (C) 2009, 2010, 2011 Nicira, Inc.

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

================
XenServer README
================

This directory contains files for seamless integration of Open vSwitch on
Citrix XenServer hosts managed by the Citrix management tools.

Files in this directory are licensed on a file-by-file basis.  Refer to each
file for details.

Most of the files in this directory are installed on a XenServer system under
the same name; underscores are replaced by slashes.  The files are:

etc_init.d_openvswitch
  Initializes Open vSwitch at boot and shuts it down at shutdown.

etc_init.d_openvswitch-xapi-update
  Init script to ensure openvswitch-cfg-update is called for the current host
  at boot.

etc_logrotate.d_openvswitch
  Ensures that logs in /var/log/openvswitch are rotated periodically and that
  appropriate daemons reopen their log files at that point.

etc_profile.d_openvswitch.sh
  Open vSwitch-related shell functions for the administrator's convenience.

etc_xapi.d_plugins_openvswitch-cfg-update
  xapi plugin script to update the cache of configuration items in the
  ovs-vswitchd configuration that are managed in the xapi database when
  integrated with Citrix management tools.

etc_xensource_scripts_vif
  Open vSwitch-aware replacement for Citrix script of the same name.

openvswitch-xen.spec
  spec file for building RPMs to install on a XenServer host.

opt_xensource_libexec_interface-reconfigure
   Open vSwitch-aware replacements for Citrix script of the same names.

opt_xensource_libexec_InterfaceReconfigureBridge.py
  See above.

opt_xensource_libexec_InterfaceReconfigure.py
  See above.

opt_xensource_libexec_InterfaceReconfigureVswitch.py
  See above.

usr_lib_xsconsole_plugins-base_XSFeatureVSwitch.py
  xsconsole plugin to configure the pool-wide configuration keys used to
  control Open vSwitch when integrated with Citrix management tools.

usr_share_openvswitch_scripts_ovs-xapi-sync
  Daemon to monitor the external_ids columns of the Bridge and Interface OVSDB
  tables for changes that require interrogating XAPI.

usr_share_openvswitch_scripts_sysconfig.template
  Template for Open vSwitch's /etc/sysconfig/openvswitch configuration file.

Open vSwitch installs a number of xen-bugtool extensions in
``/etc/xensource/bugtool`` to gather additional information useful for
debugging.  The sources for the extensions are in
``../utilities/bugtool/plugins``:

kernel-info/openvswitch.xml
  Collect kernel information relevant to Open vSwitch, such as slabinfo.

network-status/openvswitch.xml
  Collect networking information relevant to Open vSwitch.  Runs the following
  scripts, which are described below:

  * ovs-bugtool-bfd-show
  * ovs-bugtool-cfm-show
  * ovs-bugtool-fdb-show
  * ovs-bugtool-lacp-show
  * ovs-bugtool-list-dbs
  * ovs-bugtool-ovsdb-dump
  * ovs-bugtool-tc-class-show
  * ovs-bugtool-bond-show
  * ovs-bugtool-ovs-ofctl-show
  * ovs-bugtool-ovs-ofctl-dump-flows
  * ovs-bugtool-ovs-appctl-dpif
  * ovs-bugtool-coverage-show
  * ovs-bugtool-memory-show
  * ovs-bugtool-vsctl-show
  * ovs-bugtool-conntrack-dump

system-configuration/openvswitch.xml
  Collect system configuration information relevant to Open vSwitch, including
  timezone. Runs the following script which is described below:

  * ovs-bugtool-daemons-ver

system-configuration.xml
  Collect system configuration data.  This category is configured to collect up
  to 1Mb of data, take up to 60 seconds to collect data, run every time and is
  hidden from display in XenCenter.

A number of scripts are installed in ``/usr/share/openvswitch/scripts`` to
assist Open vSwitch's xen-bugtool extensions.  The sources for the scripts are
located in ``../utilities/bugtool``:

ovs-bugtool-bfd-show
  Script to dump detailed BFD information for all enabled interfaces.

ovs-bugtool-cfm-show
  Script to dump detailed CFM information for all enabled interfaces.

ovs-bugtool-fdb-show
  Script to collect a summary of learned MACs for each bridge.

ovs-bugtool-lacp-show
  Script to dump detailed LACP information for all enabled ports.

ovs-bugtool-list-dbs
  Script to list the databases controlled by ovsdb-server.

ovs-bugtool-ovsdb-dump
  Script to dump contents of Open vSwitch configuration database in
  comma-separated value format.

ovs-bugtool-tc-class-show
  Script to dump tc class configuration for all network interfaces.

ovs-bugtool-ovs-ofctl-show
  Script to dump information about flow tables and ports of each bridge.

ovs-bugtool-ovs-ofctl-dump-flows
  Script to dump openflow flows of each bridge.

ovs-bugtool-ovs-appctl-dpif
  Script to collect a summary of configured datapaths and datapath flows.

ovs-bugtool-coverage-show
  Script to count the number of times particular events occur during
  ovs-vswitchd's runtime.

ovs-bugtool-memory-show
  Script to show some basic statistics about ovs-vswitchd's memory usage.

ovs-bugtool-vsctl-show
  Script to show a brief overview of the database contents.

ovs-bugtool-conntrack-dump
  Script to show all the connection entries in the tracker.

ovs-bugtool-daemons-ver
  Script to dump version information for all Open vSwitch daemons.
