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

from Ui_MainWindow import *

class OVEMainWindow(QtGui.QMainWindow, OVECommonWindow):
    LOAD_KEY = 'MainWindow/window'
    BASE_REF=100000
    
    def __init__(self, app, loadIndex = None):
        QtGui.QMainWindow.__init__(self)
        self.ui = Ui_MainWindow()
        OVECommonWindow.__init__(self, app, loadIndex)
    
    def xon_tabWidget_currentChanged(self, value):
        self.deleteCurrentTable()
        OVECommonWindow.xon_tabWidget_currentChanged(self, value)

    def updateTable(self):
        if self.hostUuid == '':
            self.setWindowTitle('OVS Database')
            self.deleteCurrentTable()
            self.statusBar().showMessage('No host selected.  Choose File->Preferences to add a host')
        else:
            config = OVEConfig.Inst().hostFromUuid(self.hostUuid)
            self.setWindowTitle('OVS Database - '+config.get('address', ''))
            self.invalidateCurrentTable('Fetching data...')
            tabName = self.ui.tabWidget.currentWidget().objectName()
            try:
                self.setFetchSkip()
                self.currentRef += 1
                OVEFetch.Inst(self.hostUuid).getTable(self, tabName, self.currentRef)
            except Exception, e:
                OVELog("Error fetching data: "+str(e))
                self.invalidateCurrentTable(str(e))

    def timerEvent(self, event):
        OVECommonWindow.timerEvent(self, event)

    def customEvent(self, event):
        OVECommonWindow.customEvent(self, event)

    def handleFetchEvent(self, ref, values):
        tabName = self.ui.tabWidget.currentWidget().objectName()
        self.structToTable(getattr(self.ui, str(tabName)+'Table'), values)
 
    def handleFetchFailEvent(self, ref, message):
        self.invalidateCurrentTable(str(message))

    def structToTable(self, table, values):
        
        table.setUpdatesEnabled(False)
        table.setSortingEnabled(False)
        
        for result in values:
            rowNum = 0
            table.setRowCount(len(result['rows']))
            for row in result['rows']:
                table.setColumnCount(len(row))
                colNum=0
                for k in sorted(row.keys()):
                    v = row[k]
                    headerItem = QtGui.QTableWidgetItem(k)
                    table.setHorizontalHeaderItem(colNum, headerItem)
                    text = OVEUtil.paramToString(v)
                    item = QtGui.QTableWidgetItem(text)
                    longText = OVEUtil.paramToLongString(v)
                    item.setToolTip(longText)

                    table.setItem(rowNum, colNum, item)
                    colNum+=1

                rowNum+=1
                
        for i in range(0, table.columnCount()):
            table.resizeColumnToContents(i)
        for i in range(0, table.rowCount()):
            table.resizeRowToContents(i)
        
        # table.setSortingEnabled(True)
        table.setUpdatesEnabled(True)
        
        message = 'Updated at '+str(QtCore.QTime.currentTime().toString())
        if table.rowCount() == 0:
            message += ' - Table is empty'
        self.statusBar().showMessage(message)

    def invalidateCurrentTable(self, message):
        tabName = self.ui.tabWidget.currentWidget().objectName()
        self.invalidateTable(getattr(self.ui, str(tabName)+'Table'), message)

    def invalidateTable(self, table, message):
        table.setUpdatesEnabled(False)
        table.setSortingEnabled(False)
        
        for rowNum in range(0, table.rowCount()):
            for colNum in range(0, table.columnCount()):
                item = table.takeItem(rowNum, colNum)
                if item is not None:
                    item.setForeground(Qt.darkGray)
                    table.setItem(rowNum, colNum, item)
        self.statusBar().showMessage(message)
        # table.setSortingEnabled(True)
        table.setUpdatesEnabled(True)

    def deleteCurrentTable(self):
        tabName = self.ui.tabWidget.currentWidget().objectName()
        self.deleteTable(getattr(self.ui, str(tabName)+'Table'))

    def deleteTable(self, table):
        table.clear()
        table.setRowCount(0)
        table.setColumnCount(0)
        
    def saveSettings(self, index):
        settings = OVECommonWindow.saveSettings(self, index)
    
    def loadSettings(self, index):
        settings = OVECommonWindow.loadSettings(self, index)
