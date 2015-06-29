# Copyright 2015 Cloudbase Solutions Srl
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.See the
# License for the specific language governing permissions and limitations
# under the License.

PTHREAD_TEMP_DIR=`echo "$(PTHREAD_LDFLAGS)" | sed 's|^.\(.*\).$:\1||'`
windows_installer: all
#Userspace files needed for the installer
	cp -f $(top_srcdir)/datapath-windows/misc/OVS.psm1 windows/ovs-windows-installer/Services/OVS.psm1
	cp -f $(top_srcdir)/vswitchd/vswitch.ovsschema windows/ovs-windows-installer/Services/vswitch.ovsschema
	cp -f $(top_srcdir)/vswitchd/ovs-vswitchd.exe windows/ovs-windows-installer/Services/ovs-vswitchd.exe
	cp -f $(top_srcdir)/ovsdb/ovsdb-server.exe windows/ovs-windows-installer/Services/ovsdb-server.exe
	cp -f $(top_srcdir)/utilities/*.exe windows/ovs-windows-installer/Binaries/
	cp -f $(top_srcdir)/utilities/*.pdb windows/ovs-windows-installer/Symbols/
	cp -f $(top_srcdir)/ovsdb/ovsdb-client.exe windows/ovs-windows-installer/Binaries/ovsdb-client.exe
	cp -f $(top_srcdir)/ovsdb/ovsdb-tool.exe windows/ovs-windows-installer/Binaries/ovsdb-tool.exe
	cp -f $(top_srcdir)/ovsdb/ovsdb-client.pdb windows/ovs-windows-installer/Symbols/
	cp -f $(top_srcdir)/ovsdb/ovsdb-tool.pdb windows/ovs-windows-installer/Symbols/
#Third party files needed by the installer
	cp -f $(PTHREAD_TEMP_DIR)/../../dll/x86/*.dll windows/ovs-windows-installer/Binaries/
	cp -f "/c/Program Files (x86)/Common Files/Merge Modules/Microsoft_VC120_CRT_x86.msm" windows/ovs-windows-installer/Redist/Microsoft_VC120_CRT_x86.msm
#Forwarding extension files needed for the installer
	cp -f $(top_srcdir)/datapath-windows/x64/Win8$(VSTUDIO_CONFIG)/package/ovsext.cat windows/ovs-windows-installer/Driver/Win8/ovsext.cat
	cp -f $(top_srcdir)/datapath-windows/x64/Win8$(VSTUDIO_CONFIG)/package/ovsext.inf windows/ovs-windows-installer/Driver/Win8/ovsext.inf
	cp -f $(top_srcdir)/datapath-windows/x64/Win8$(VSTUDIO_CONFIG)/package/OVSExt.sys windows/ovs-windows-installer/Driver/Win8/OVSExt.sys
	cp -f $(top_srcdir)/datapath-windows/x64/Win8.1$(VSTUDIO_CONFIG)/package/ovsext.cat windows/ovs-windows-installer/Driver/Win8.1/ovsext.cat
	cp -f $(top_srcdir)/datapath-windows/x64/Win8.1$(VSTUDIO_CONFIG)/package/ovsext.inf windows/ovs-windows-installer/Driver/Win8.1/ovsext.inf
	cp -f $(top_srcdir)/datapath-windows/x64/Win8.1$(VSTUDIO_CONFIG)/package/ovsext.sys windows/ovs-windows-installer/Driver/Win8.1/ovsext.sys
	MSBuild.exe windows/ovs-windows-installer.sln /target:Build /property:Configuration="Release"

EXTRA_DIST += \
	windows/.gitignore \
	windows/automake.mk \
	windows/README.rst \
	windows/ovs-windows-installer.sln \
	windows/ovs-windows-installer/Actions/OVSActions.js \
	windows/ovs-windows-installer/CustomActions.wxs \
	windows/ovs-windows-installer/Dialogs/BeginningDialog.wxs \
	windows/ovs-windows-installer/Dialogs/MyEndDialog.wxs \
	windows/ovs-windows-installer/Dialogs/MyTroubleshootDialog.wxs \
	windows/ovs-windows-installer/Dialogs/UserFinishDialog.wxs \
	windows/ovs-windows-installer/License.rtf \
	windows/ovs-windows-installer/Product.wxs \
	windows/ovs-windows-installer/UI.wxs \
	windows/ovs-windows-installer/images/bannrbmp.bmp \
	windows/ovs-windows-installer/images/dlgbmp.bmp \
	windows/ovs-windows-installer/ovs-windows-installer.wixproj

