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
from Ui_LogWindow import *

class OVELogWindow(QtGui.QDialog):
    LOAD_KEY = 'LogWindow/window'
    def __init__(self, app):
        QtGui.QDialog.__init__(self)
        self.app = app
        self.ui = Ui_LogWindow()
        self.ui.setupUi(self)
        if self.isLoadable():
            self.loadSettings()
        self.connect(OVELogger.Inst(), QtCore.SIGNAL("logUpdated()"), self.logUpdated)
        self.connect(self.ui.buttonBox, QtCore.SIGNAL("clicked(QAbstractButton *)"), self.xon_actionButton_Box_clicked)
        
    def xon_actionButton_Box_clicked(self, button):
        role = self.ui.buttonBox.buttonRole(button)
        if role == QtGui.QDialogButtonBox.ResetRole:
            OVELogger.Inst().reset()
            OVELog("Log reset")
        
    def logUpdated(self):
        self.ui.textBrowser.setText("\n".join(OVELogger.Inst().contents))
        self.ui.textBrowser.moveCursor(QtGui.QTextCursor.End)
        self.ui.textBrowser.ensureCursorVisible()

    def saveSettings(self):
        key = self.LOAD_KEY
        settings = QtCore.QSettings()
        settings.setValue(key+"/loadable", QVariant(True))
        settings.setValue(key+"/pos", QVariant(self.pos()))
        settings.setValue(key+"/size", QVariant(self.size()))
        settings.setValue(key+"/visible", QVariant(self.isVisible()))
    
    def loadSettings(self):
        key = self.LOAD_KEY
        settings = QtCore.QSettings()
        pos = settings.value(key+"/pos", QVariant(QtCore.QPoint(200, 200))).toPoint()
        size = settings.value(key+"/size", QVariant(QtCore.QSize(400, 400))).toSize()
        visible = settings.value(key+"/visible", QVariant(True)).toBool()
        self.resize(size)
        self.move(pos)
        self.setVisible(visible)

    @classmethod
    def isLoadable(cls):
        key = cls.LOAD_KEY
        settings = QtCore.QSettings()
        return settings.value(key+"/loadable", QVariant(False)).toBool()
