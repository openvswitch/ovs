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
from OVELogger import *
from Ui_HostWindow import *

class OVEHostWindow(QtGui.QDialog):
    DEFAULT_CONNECT_TARGET = 'unix:/var/run/openvswitch/db.sock'
    def __init__(self, parent, currentValues = None):
        QtGui.QDialog.__init__(self, parent)
        self.ui = Ui_HostWindow()
        self.ui.setupUi(self)
        self.resize(-1, -1)
        self.connect(self.ui.buttonBox, QtCore.SIGNAL("clicked(QAbstractButton *)"), self.xon_actionButton_Box_clicked)
        if currentValues is not None:
            self.ui.hostAddressEdit.setText(currentValues['address'])
            self.ui.hostPasswordEdit.setText(currentValues['password'])
            self.ui.hostConnectTarget.setText(currentValues.get('connectTarget', self.DEFAULT_CONNECT_TARGET))
            self.uuid = currentValues.get('uuid', str(uuid.uuid4()))
        else:
            self.ui.hostConnectTarget.setText(self.DEFAULT_CONNECT_TARGET)
            self.uuid = str(uuid.uuid4())
            self.accepted = None
    
    def xon_actionButton_Box_clicked(self, button):
        role = self.ui.buttonBox.buttonRole(button)
        if role == QtGui.QDialogButtonBox.AcceptRole:
            self.accepted = True
            self.close()
        elif role == QtGui.QDialogButtonBox.RejectRole:
            self.accepted = False
            self.close()

    def record(self):
        return {
            'accepted' : self.accepted,
            'uuid' : self.uuid,
            'address' : str(self.ui.hostAddressEdit.text()),
            'password' : str(self.ui.hostPasswordEdit.text()),
            'connectTarget' : str(self.ui.hostConnectTarget.text())
            }

