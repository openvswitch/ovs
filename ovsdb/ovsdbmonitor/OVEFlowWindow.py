# Copyright (c) 2011 Nicira, Inc.
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

from OVECommonWindow import *

from Ui_FlowWindow import *

import re

class OVEFlowWindow(QtGui.QMainWindow, OVECommonWindow):
    LOAD_KEY = 'FlowWindow/window'
    COMMAND_OVS_DPCTL='/usr/bin/ovs-dpctl'
    BASE_REF=200000
    
    def __init__(self, app, loadIndex = None):
        QtGui.QMainWindow.__init__(self)
        self.ui = Ui_FlowWindow()
        self.dpNames = []
        self.dpTables = []
        self.currentOpIndex = None
        self.resizeCount = []
        self.ssgChecked = False
        self.ssgText = ''
        self.lastTime = None
        self.lastByteCount = 0
        OVECommonWindow.__init__(self, app, loadIndex)

        self.updateSsgList()
        self.updateDatapaths()
        self.updateSsgState()

        self.connect(self.ui.fetchPathsButton, QtCore.SIGNAL("clicked()"), self.xon_fetchPathsButton_clicked)
        self.connect(self.ui.ssgSaveButton, QtCore.SIGNAL("clicked()"), self.xon_ssgSaveButton_clicked)
        self.connect(self.ui.ssgDeleteButton, QtCore.SIGNAL("clicked()"), self.xon_ssgDeleteButton_clicked)
        self.connect(self.ui.ssgComboBox, QtCore.SIGNAL("activated(int)"), self.xon_ssgComboBox_activated)
        self.connect(self.ui.ssgComboBox, QtCore.SIGNAL("editTextChanged(QString)"), self.xon_ssgComboBox_editTextChanged)
        self.connect(self.ui.ssgCheckBox, QtCore.SIGNAL("stateChanged(int)"), self.xon_ssgCheckBox_stateChanged)
        
    
    def xon_fetchPathsButton_clicked(self):
        self.updateDatapaths()
    
    def xon_hostComboBox_currentIndexChanged(self, index):
        OVECommonWindow.xon_hostComboBox_currentIndexChanged(self, index)
        if (index >= 0):
            self.updateDatapaths()
    
    def xon_ssgSaveButton_clicked(self):
        if self.ssgText not in OVEConfig.Inst().ssgList:
            OVEConfig.Inst().ssgList.append(self.ssgText)
            OVEConfig.Inst().saveConfig()
        self.updateSsgList()
        
    def updateSsgList(self):
        currentSsgText = self.ssgText
        self.ui.ssgComboBox.clear()
        isFound = False
        for i, ssgText in enumerate(OVEConfig.Inst().ssgList):
            self.ui.ssgComboBox.addItem(ssgText)
            if ssgText == currentSsgText:
                # This is the currently selected item
                self.ui.ssgComboBox.setCurrentIndex(i)
                isFound = True
        
        if not isFound:
            self.ui.ssgComboBox.setCurrentIndex(-1)
            self.ui.ssgComboBox.lineEdit().setText(currentSsgText)

    def xon_ssgDeleteButton_clicked(self):
        if self.ssgText in OVEConfig.Inst().ssgList:
            OVEConfig.Inst().ssgList.remove(self.ssgText)
            self.ssgText = ''
            OVEConfig.Inst().saveConfig()
        self.updateSsgList()

    def xon_ssgComboBox_activated(self, index):
        if (index >= 0):
            itemData = self.ui.ssgComboBox.itemText(index)
            self.ssgText = str(itemData)
            self.updateTable()
    
    def xon_ssgComboBox_editTextChanged(self, text):
        self.ssgText = str(text)
        self.statusBar().showMessage('Remote command is: '+self.updateCommand())
        present = (self.ssgText in OVEConfig.Inst().ssgList)
        self.ui.ssgDeleteButton.setEnabled(present)
        self.ui.ssgSaveButton.setEnabled(not present)
    
    def xon_ssgCheckBox_stateChanged(self, state):
        self.ssgChecked = (state == Qt.Checked)
        self.updateTable()
    
    def xon_configUpdated(self):
        OVECommonWindow.xon_configUpdated(self)
        self.updateSsgList()
        self.updateDatapaths()
    
    def timerEvent(self, event):
        OVECommonWindow.timerEvent(self, event)

    def customEvent(self, event):
        OVECommonWindow.customEvent(self, event)
    
    def updateDatapaths(self):
        if self.hostUuid == '':
            self.statusBar().showMessage('No host selected')
        else:
            self.currentRef += 1
            self.currentOp = 'dump-dps'
            command = self.COMMAND_OVS_DPCTL+' dump-dps'
            OVEFetch.Inst(self.hostUuid).execCommandFramed(self, self.currentRef, command)
    
    def rebuildTables(self):
        self.ui.tabWidget.clear() # Let the garbage collector delete the pages
        self.dpTables = []
        self.dpFlows = []
        self.resizeCount = []
        headings = OVEUtil.flowDecodeHeadings()
        
        for dpName in self.dpNames:
            pageWidget = QtGui.QWidget()
            pageWidget.setObjectName(dpName+'_page')
            gridLayout = QtGui.QGridLayout(pageWidget)
            gridLayout.setObjectName(dpName+"_gridLayout")
            table = QtGui.QTableWidget(pageWidget)
            table.setObjectName(dpName+"_table")
            table.setColumnCount(len(headings))
            table.setRowCount(0)
            gridLayout.addWidget(table, 0, 0, 1, 1)
            self.dpTables.append(table)
            self.ui.tabWidget.addTab(pageWidget, dpName)
            self.dpFlows.append([])
            self.resizeCount.append(0)
            for i, heading in enumerate(headings):
                table.setHorizontalHeaderItem(i, QtGui.QTableWidgetItem(heading))

            table.setSortingEnabled(True)
            
            table.sortItems(OVEUtil.getFlowColumn('source mac'))
            table.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
    
    def updateSsgState(self):
        self.ui.ssgCheckBox.setChecked(self.ssgChecked)
    
    def updateCommand(self, overrideText = None):
        command = self.COMMAND_OVS_DPCTL+' dump-flows '
        if self.currentOpIndex is not None:
            command += self.dpNames[self.currentOpIndex]
        exp = None
        if overrideText is not None:
                exp = overrideText
        elif self.ssgChecked:
                exp = self.ssgText
                
        if exp is not None:
            opts='-E '
            if exp.startswith('!'):
                exp =exp[1:]
                opts += '-v '
            command += " | grep "+opts+"'"+exp+"' ; test ${PIPESTATUS[0]} -eq 0 "

        return command
    
    def updateTable(self):
        if self.hostUuid == '':
            self.statusBar().showMessage('No host selected')
            self.setWindowTitle('OVS Flows')
        elif len(self.dpNames) > 0:
            config = OVEConfig.Inst().hostFromUuid(self.hostUuid)
            self.setWindowTitle('OVS Flows - '+config.get('address', ''))
            try:
                self.setFetchSkip()
                self.statusBar().showMessage('Fetching data...') 
                self.currentRef += 1
                self.currentOp = 'dump-flows'
                self.currentOpIndex = self.ui.tabWidget.currentIndex()
                OVEFetch.Inst(self.hostUuid).execCommandFramed(self, self.currentRef, self.updateCommand())
            except Exception, e:
                message = 'Update failed: '+str(e)
                OVELog(message)
                self.statusBar().showMessage(message)
    
    def writeCurrentTable(self):
        index = self.ui.tabWidget.currentIndex()
        actionsColumn = OVEUtil.getFlowColumn('actions')
        usedColumn = OVEUtil.getFlowColumn('used')
        srcMacColumn = OVEUtil.getFlowColumn('source mac')
        destMacColumn = OVEUtil.getFlowColumn('destination mac')
        srcIPColumn = OVEUtil.getFlowColumn('source ip')
        destIPColumn = OVEUtil.getFlowColumn('destination ip')
        inportColumn = OVEUtil.getFlowColumn('inport')
        vlanColumn = OVEUtil.getFlowColumn('vlan')
        bytesColumn = OVEUtil.getFlowColumn('bytes')
        
        byteCount = 0
        try:
            table = self.dpTables[index]
            table.setUpdatesEnabled(False)
            table.setSortingEnabled(False)
            try:
                flows = self.dpFlows[index]
                table.setRowCount(len(flows))
                if len(flows) > 0:
                    table.setColumnCount(len(flows[0]))
                for rowNum, flow in enumerate(flows):
                    
                    inport = flow[inportColumn]
                    if flow[actionsColumn] == 'drop':
                        baseLum=172
                    else:
                        baseLum=239
                    background = QtGui.QColor(baseLum+16*(inport % 2), baseLum+8*(inport % 3), baseLum+4*(inport % 5))
                    if flow[usedColumn] == 'never':
                        colour = QtGui.QColor(112,112,112)
                    else:
                        colour = Qt.black
                        
                    for colNum, data in enumerate(flow):
                        item = None
                        try:
                            item = table.takeItem(rowNum, colNum)
                        except:
                            pass
                        if item is None:
                            item = QtGui.QTableWidgetItem('')

                        if colNum == vlanColumn:
                            item.setBackground(QtGui.QColor(255-(10*data % 192), 255-((17*data) % 192), 255-((37*data) % 192)))
                        elif colNum == srcMacColumn or colNum == destMacColumn:
                            cols = [int(x, 16) for x in data.split(':')]
                            item.setBackground(QtGui.QColor(255-cols[2]*cols[3] % 192, 255-cols[3]*cols[4] % 192, 255-cols[4]*cols[5] % 192))
                        elif re.match(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', str(data)):
                            cols = [int(x) for x in data.split('.')]
                            item.setBackground(QtGui.QColor(255-cols[1]*cols[2] % 192, 255-cols[2]*cols[3] % 192, 255-cols[3]*cols[0] % 192))
                        else:
                            item.setBackground(background)
                            item.setForeground(colour)
                            
                        if colNum == bytesColumn:
                            byteCount += int(data)
                            
                        # PySide 0.2.3 fails to convert long ints to QVariants and logs 'long int too large to convert to int' errors
                        try:
                            item.setData(Qt.DisplayRole, QVariant(data))
                            item.setToolTip(str(data))
                        except Exception, e:
                            item.setText('Error: See tooltip')
                            item.setToolTip(str(e))
                        table.setItem(rowNum, colNum, item)
                
                if self.resizeCount[index] < 2:
                    self.resizeCount[index] += 1
                    for i in range(0, table.columnCount()):
                        table.resizeColumnToContents(i)

            finally:
                table.setUpdatesEnabled(True)
                table.setSortingEnabled(True)

            message = 'Updated at '+str(QtCore.QTime.currentTime().toString())
            
            if self.lastTime is not None:
                timeDiff = time.time() - self.lastTime
                byteDiff = byteCount - self.lastByteCount
                bitRate = long(8 * byteDiff / timeDiff)
                if abs(bitRate) < 10*2**20:
                    message += ' ('+str(bitRate/2**10)+' kbit/s)'
                elif abs(bitRate) < 10*2**30:
                    message += ' ('+str(bitRate/2**20)+' Mbit/s)'
                else:
                    message += ' ('+str(bitRate/2**30)+' Gbit/s)'
                
            self.lastByteCount = byteCount
            self.lastTime = time.time()
            if table.rowCount() == 0:
                message += ' - Table is empty'
            self.statusBar().showMessage(message)

        except Exception, e:
            message = 'Table update failed: '+str(e)
            OVELog(message)
            self.statusBar().showMessage(message)

    def handleFetchEvent(self, ref, values):
        if self.currentOp == 'dump-dps':
            self.dpNames =values.strip().split('\n')
            self.rebuildTables()
            self.updateTable()
        elif self.currentOp == 'dump-flows':
            self.dpFlows[self.currentOpIndex] = OVEUtil.decodeFlows(values)
            self.writeCurrentTable()

    def handleFetchFailEvent(self, ref, message):
        self.statusBar().showMessage(message)
        OVELog('Fetch ('+self.currentOp+') failed')

    def customEvent(self, event):
        OVECommonWindow.customEvent(self, event)
        
    def saveSettings(self, index):
        settings, key = OVECommonWindow.saveSettings(self, index)
        settings.setValue(key+"/ssgText", QVariant(self.ssgText))
        settings.setValue(key+"/ssgChecked", QVariant(self.ssgChecked))
        
    def loadSettings(self, index):
        settings, key = OVECommonWindow.loadSettings(self, index)
        self.ssgText = str(settings.value(key+"/ssgText", QVariant('10\.80\.226\..*')).toString())
        self.ssgChecked = settings.value(key+"/ssgChecked", QVariant(False)).toBool()
        self.ssgRe = re.compile(self.ssgText)
