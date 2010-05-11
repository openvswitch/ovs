# Copyright (c) 2010 Citrix Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from OVEStandard import *
from OVEConfig import *
from OVEFetch import *

from OVEConfigWindow import *
from OVEFlowWindow import *
from OVELogWindow import *
from OVEMainWindow import *

class OVEApp:
    def __init__(self):
        self.app = globalApp
        self.app.setOrganizationName("Citrix_Systems_Inc")
        self.app.setOrganizationDomain("citrix.com")
        self.app.setApplicationName("ovsdbmonitor")
        self.mainWindows = []
        self.flowWindows = []
        self.configWindow = None

    def enter(self):
        if len(OVEConfig.Inst().hosts) < 1:
            self.showConfig(True)
            QtGui.QMessageBox.information(
                    None, "OVSDB Monitor",
                    "This application browses openvswitch databases on remote hosts.  Please add one or more openvswitch hosts to continue")
        self.loadMainWindows()
        self.loadFlowWindows()
        if len(self.mainWindows) == 0 and len(self.flowWindows) == 0:
            self.newMainWindow()
        self.newLogWindow()
        # Reactor must be started after the event loop is running, so use a zero timeout
        QtCore.QTimer.singleShot(0, OVEFetch.startReactor)
        OVELog("Application started")
        retCode = self.app.exec_()
        index = 0
        for mainWindow in self.mainWindows:
            if mainWindow.isVisible():
                mainWindow.saveSettings(index)
                index += 1 # Indent intentional
        OVEMainWindow.terminateSettings(index)
        index = 0
        for flowWindow in self.flowWindows:
            if flowWindow.isVisible():
                flowWindow.saveSettings(index)
                index += 1 # Indent intentional            
        OVEFlowWindow.terminateSettings(index)
        self.logWindow.saveSettings()
    
    def quit(self):
        self.app.quit()
    
    def showLog(self, value):
        if value:
            self.logWindow.hide()
            self.logWindow.show()
        else:
            self.logWindow.hide()

    def showConfig(self, value):
        if value:
            del self.configWindow
            self.configWindow = OVEConfigWindow(self)
            self.configWindow.show()
        else:
            self.configWindow.hide()

    def newMainWindow(self, loadIndex = None):
        self.mainWindows.append(OVEMainWindow(self, loadIndex))
        self.mainWindows[-1].show()

    def newFlowWindow(self, loadIndex = None):
        self.flowWindows.append(OVEFlowWindow(self, loadIndex))
        self.flowWindows[-1].show()

    def newLogWindow(self):
        self.logWindow = OVELogWindow(self)

    def loadMainWindows(self):
        for loadIndex in range(0, 100):
            if OVEMainWindow.isLoadable(loadIndex):
                self.newMainWindow(loadIndex)
            else:
                break

    def loadFlowWindows(self):
        for loadIndex in range(0, 100):
            if OVEFlowWindow.isLoadable(loadIndex):
                self.newFlowWindow(loadIndex)
            else:
                break
