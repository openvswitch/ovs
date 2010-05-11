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

from OVEStandard import *
from OVEConfig import *
from OVELogger import *
from Ui_ConfigWindow import *

from OVEHostWindow import *

class OVEConfigWindow(QtGui.QDialog):
    def __init__(self, app):
        QtGui.QDialog.__init__(self)
        self.app = app
        self.ui = Ui_ConfigWindow()
        self.ui.setupUi(self)

        self.connect(self.ui.hostAddButton, QtCore.SIGNAL("clicked()"), self.xon_hostAddButton_clicked)
        self.connect(self.ui.hostEditButton, QtCore.SIGNAL("clicked()"), self.xon_hostEditButton_clicked)
        self.connect(self.ui.hostDeleteButton, QtCore.SIGNAL("clicked()"), self.xon_hostDeleteButton_clicked)
        self.connect(self.ui.buttonBox, QtCore.SIGNAL("clicked(QAbstractButton *)"), self.xon_actionButton_Box_clicked)
        self.connect(self.ui.hostList, QtCore.SIGNAL("currentItemChanged(QListWidgetItem *,  QListWidgetItem *)"), self.xon_hostList_currentItemChanged)
        self.connect(self.ui.logTrafficCheckBox, QtCore.SIGNAL("stateChanged(int)"), self.xon_logTrafficCheckBox_stateChanged)
        self.connect(self.ui.truncateUuidsCheckBox, QtCore.SIGNAL("stateChanged(int)"), self.xon_truncateUuidsCheckBox_stateChanged)
        self.readConfig()
        self.updateWidgets()
    
    def handleHostWindowRecord(self, record, isEdit):
        if record['accepted'] and record['address'].strip() != '':
            currentRow = self.ui.hostList.currentRow()
            if isEdit:
                self.configHosts[currentRow] = record
            else:
                self.configHosts.append(record)

        self.updateWidgets()

    def xon_hostAddButton_clicked(self):
        hostWindow = OVEHostWindow(self)
        hostWindow.exec_()
        self.handleHostWindowRecord(hostWindow.record(), False)

    def xon_hostEditButton_clicked(self):
        if self.ui.hostList.currentItem() is None:
            pass # OVELog('No item to edit')
        else:
            currentRow = self.ui.hostList.currentRow()
            hostWindow = OVEHostWindow(self, self.configHosts[currentRow])
            hostWindow.exec_()
            self.handleHostWindowRecord(hostWindow.record(), True)

    def xon_hostDeleteButton_clicked(self):
        if self.ui.hostList.currentItem() is not None:
            currentRow = self.ui.hostList.currentRow()
            del self.configHosts[currentRow]
            self.updateWidgets()

    def xon_actionButton_Box_clicked(self, button):
        role = self.ui.buttonBox.buttonRole(button)
        if role == QtGui.QDialogButtonBox.AcceptRole:
            self.writeConfig()
            self.close()
        elif role == QtGui.QDialogButtonBox.ApplyRole:
            self.writeConfig()
        elif role == QtGui.QDialogButtonBox.RejectRole:
            if self.configChanged():
                self.close()
            else:
                ret = QtGui.QMessageBox.warning(
                    self, "OVSDB Monitor",
                    "Changes not applied. Discard?",
                    QtGui.QMessageBox.Discard | QtGui.QMessageBox.Cancel | QtGui.QMessageBox.Apply,
                    QtGui.QMessageBox.Discard)
                
                if ret == QtGui.QMessageBox.Apply:
                    self.writeConfig()
                if ret != QtGui.QMessageBox.Cancel:
                    self.close()

    def xon_hostList_currentItemChanged(self, current, previous):
        editable = (current is not None)
        self.ui.hostEditButton.setEnabled(editable)
        self.ui.hostDeleteButton.setEnabled(editable)

    def xon_logTrafficCheckBox_stateChanged(self, value):
        self.configLogTraffic = (value == Qt.Checked)
    
    def xon_truncateUuidsCheckBox_stateChanged(self, value):
        self.configTruncateUuids = (value == Qt.Checked)
    
    def updateWidgets(self):
        self.ui.hostList.clear()
        for host in self.configHosts:
            self.ui.hostList.addItem(host['address'])
        self.ui.logTrafficCheckBox.setChecked(self.configLogTraffic)
        self.ui.truncateUuidsCheckBox.setChecked(self.configTruncateUuids)

    def configChanged(self):
        return (
            (self.configHosts == OVEConfig.Inst().hosts) and
            (self.configLogTraffic == (OVEConfig.Inst().logTraffic))and
            (self.configTruncateUuids == (OVEConfig.Inst().truncateUuids))
        )
        
    def readConfig(self):
        self.configHosts = deepcopy(OVEConfig.Inst().hosts)
        self.configLogTraffic = OVEConfig.Inst().logTraffic
        self.configTruncateUuids = OVEConfig.Inst().truncateUuids
        
    def writeConfig(self):
        OVEConfig.Inst().hosts = deepcopy(self.configHosts)
        OVEConfig.Inst().logTraffic = self.configLogTraffic
        OVEConfig.Inst().truncateUuids = self.configTruncateUuids
        OVEConfig.Inst().saveConfig()

    
