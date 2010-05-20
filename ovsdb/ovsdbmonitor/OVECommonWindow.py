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
from OVEFetch import *
from OVELogger import *
from OVEUtil import *

from Ui_MainWindow import *

class OVECommonWindow:
    def __init__(self, app, loadIndex = None):
        self.app = app
        self.intervalTimerId = None        
        self.hostUuid = ''
        self.intervalChecked = True
        self.intervalSeconds = 5
        self.fetchSkip = 0
        self.currentRef = self.BASE_REF
                
        self.ui.setupUi(self)
        
        if loadIndex is not None:
            self.loadSettings(loadIndex)
        
        self.connect(self.ui.actionNew_DB_Window, QtCore.SIGNAL("triggered()"), self.xon_actionNew_DB_Window_triggered)
        self.connect(self.ui.actionNew_Flow_Window, QtCore.SIGNAL("triggered()"), self.xon_actionNew_Flow_Window_triggered)
        self.connect(self.ui.actionShow_Log, QtCore.SIGNAL("triggered()"), self.xon_actionShow_Log_triggered)
        self.connect(self.ui.actionPreferences, QtCore.SIGNAL("triggered()"), self.xon_actionPreferences_triggered)
        self.connect(self.ui.actionQuit, QtCore.SIGNAL("triggered()"), self.xon_actionQuit_triggered)
        self.connect(self.ui.fetchButton, QtCore.SIGNAL("clicked()"), self.xon_fetchButton_clicked)
        self.connect(self.ui.tabWidget, QtCore.SIGNAL("currentChanged(int)"), self.xon_tabWidget_currentChanged)
        self.connect(self.ui.hostComboBox, QtCore.SIGNAL("currentIndexChanged(int)"), self.xon_hostComboBox_currentIndexChanged)
        self.connect(self.ui.intervalCheckBox, QtCore.SIGNAL("stateChanged(int)"), self.xon_intervalCheckBox_stateChanged)
        self.connect(self.ui.intervalSpinBox, QtCore.SIGNAL("valueChanged(int)"), self.xon_intervalSpinBox_valueChanged)
        self.connect(OVEConfig.Inst(), QtCore.SIGNAL("configUpdated()"), self.xon_configUpdated)
        
        self.updateHosts()
        self.updateInterval()
        self.updateIntervalState()
        self.updateTable()
        
    def xon_actionNew_DB_Window_triggered(self):
        self.app.newMainWindow()
 
    def xon_actionNew_Flow_Window_triggered(self):
        self.app.newFlowWindow()

    def xon_actionShow_Log_triggered(self):
        self.app.showLog(True)

    def xon_actionPreferences_triggered(self):
        self.app.showConfig(True)

    def xon_actionQuit_triggered(self):
        self.app.quit()
    
    def xon_tabWidget_currentChanged(self, value):
        self.updateTable()
        
    def xon_fetchButton_clicked(self):
        self.updateTable()
    
    def xon_configUpdated(self):
        self.updateHosts()
    
    def xon_hostComboBox_currentIndexChanged(self, index):
        if (index >= 0):
            itemData = self.ui.hostComboBox.itemData(index)
            self.hostUuid = str(itemData.toString())
            self.deleteCurrentTable()
            self.updateTable()
    
    def xon_intervalCheckBox_stateChanged(self, state):
        self.intervalChecked = (state == Qt.Checked)
        self.updateIntervalState()
    
    def xon_intervalSpinBox_valueChanged(self, value):
        self.intervalSeconds = value
        self.updateIntervalState()
    
    def updateIntervalState(self):
        if self.intervalTimerId is not None:
            self.killTimer(self.intervalTimerId)
        if self.intervalChecked:
            self.intervalTimerId = self.startTimer(1000*self.intervalSeconds)
    
    def updateHosts(self):
        currentHostUuid = self.hostUuid # self.hostUuid will change due to currentIndexChanged events as we rebuild the combo box
        self.hostUuid = ''
        self.ui.hostComboBox.clear()
        for i, host in enumerate(OVEConfig.Inst().hosts):
            self.ui.hostComboBox.addItem(host['address'], QVariant(host['uuid']))
            if host['uuid'] == currentHostUuid:
                # This is the currently selected host
                self.ui.hostComboBox.setCurrentIndex(i)
        if len(OVEConfig.Inst().hosts) == 0:
            self.ui.hostComboBox.addItem('(No hosts configured)', QVariant(''))
            
    def updateInterval(self):
        self.ui.intervalCheckBox.setChecked(self.intervalChecked)
        self.ui.intervalSpinBox.setValue(self.intervalSeconds)
 
    def handleFetchEvent(self, ref, values):
        OVELog('Unhandled FetchEvent')
 
    def handleFetchFailEvent(self, ref, message):
        OVELog('Unhandled FetchFailEvent')
 
    def setFetchSkip(self):
        # Call before sending a request via OVEFetch
        self.fetchSkip = 6
 
    def timerEvent(self, event):
        if event.timerId() == self.intervalTimerId:
            if self.fetchSkip > 0:
                self.statusBar().showMessage('Fetch stalled... resend in '+str(self.fetchSkip*self.intervalSeconds)+'s') 
                self.fetchSkip -= 1
                if self.fetchSkip == 0:
                    # Stall has timed out. The connection might have hung so reset.  Seems to happen with PySide only
                    OVEFetch.Inst(self.hostUuid).resetTransport()
            else:
                self.updateTable()
        else:
            QtGui.QMainWindow.timerEvent(self, event)
 
    def customEvent(self, event):
        if event.type() == OVEFetchEvent.TYPE:
            if isinstance(event, OVEFetchEvent):
                # The right way to get data
                ref = event.ref
                values = event.data
            else:
                # Workaround for PySide issue
                ref = OVEFetch.Inst(self.hostUuid).snoopRef(self)
                values = OVEFetch.Inst(self.hostUuid).snoopValues(self)
            try:
                if ref == self.currentRef:
                    self.fetchSkip = 0
                    self.currentRef += 1 # PySide workaround
                    self.handleFetchEvent(ref, values)
                else:
                    # If refs don't match this event relates to a request before the current one.  We've moved
                    # on since then, e.g. changed the table we've viewing, so ignore it
                    if OVEConfig.Inst().logTraffic:
                        OVELog('FetchEvent ref mismatch '+str(ref)+' != '+str(self.currentRef))
            except Exception, e:
                OVELog("Error during data handling: "+str(e))

        elif event.type() == OVEFetchFailEvent.TYPE:
            if isinstance(event, OVEFetchFailEvent):
                # The right way to get data
                ref = event.ref
                message = event.message
            else:
                # Workaround for PySide issue
                ref = OVEFetch.Inst(self.hostUuid).snoopRef(self)
                message = OVEFetch.Inst(self.hostUuid).snoopMessage(self)
            if message is not None:
                OVELog(message)
            if ref == self.currentRef:
                self.fetchSkip = 0
                self.currentRef += 1 # PySide workaround
                self.handleFetchFailEvent(ref, message)
            else:
                if OVEConfig.Inst().logTraffic:
                    OVELog('FetchFailEvent ref mismatch '+str(ref)+' != '+str(self.currentRef))
 
    def deleteCurrentTable(self):
        pass
 
    def saveSettings(self, index):
        key = self.LOAD_KEY+str(index)
        settings = QtCore.QSettings()
        settings.setValue(key+"/loadable", QVariant(True))
        settings.setValue(key+"/pos", QVariant(self.pos()))
        settings.setValue(key+"/size", QVariant(self.size()))
        settings.setValue(key+"/hostUuid", QVariant(self.hostUuid))
        settings.setValue(key+"/intervalChecked", QVariant(self.intervalChecked))
        settings.setValue(key+"/intervalSeconds", QVariant(self.intervalSeconds))

        return settings, key
    
    def loadSettings(self, index):
        key = self.LOAD_KEY+str(index)
        settings = QtCore.QSettings()
        pos = settings.value(key+"/pos", QVariant(QtCore.QPoint(200, 200))).toPoint()
        size = settings.value(key+"/size", QVariant(QtCore.QSize(400, 400))).toSize();

        self.hostUuid = str(settings.value(key+"/hostUuid", QVariant('Unloaded')).toString())
        self.intervalChecked = settings.value(key+"/intervalChecked", QVariant(True)).toBool()
        self.intervalSeconds = settings.value(key+"/intervalSeconds", QVariant(5)).toInt()[0]
        self.resize(size)
        self.move(pos)
        return settings, key

    @classmethod
    def terminateSettings(self, index):
        key = self.LOAD_KEY+str(index)
        settings = QtCore.QSettings()
        settings.setValue(key+"/loadable", QVariant(False))
        settings.sync()
        
    @classmethod
    def isLoadable(cls, index):
        key = cls.LOAD_KEY+str(index)
        settings = QtCore.QSettings()
        return settings.value(key+"/loadable", QVariant(False)).toBool()
        
