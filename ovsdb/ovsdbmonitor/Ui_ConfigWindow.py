# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ConfigWindow.ui'
#
# Created: Fri May  7 17:20:33 2010
#      by: PyQt4 UI code generator 4.4.2
#
# WARNING! All changes made in this file will be lost!

try:
    from OVEStandard import globalForcePySide
    if globalForcePySide: raise Exception()
    from PyQt4 import QtCore, QtGui
except:
    from PySide import QtCore, QtGui

class Ui_ConfigWindow(object):
    def setupUi(self, ConfigWindow):
        ConfigWindow.setObjectName("ConfigWindow")
        ConfigWindow.resize(386,303)
        ConfigWindow.setFocusPolicy(QtCore.Qt.TabFocus)
        self.gridLayout = QtGui.QGridLayout(ConfigWindow)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.tabWidget = QtGui.QTabWidget(ConfigWindow)
        self.tabWidget.setObjectName("tabWidget")
        self.hosts = QtGui.QWidget()
        self.hosts.setObjectName("hosts")
        self.layoutWidget = QtGui.QWidget(self.hosts)
        self.layoutWidget.setGeometry(QtCore.QRect(10,10,341,194))
        self.layoutWidget.setObjectName("layoutWidget")
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.layoutWidget)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.hostList = QtGui.QListWidget(self.layoutWidget)
        self.hostList.setObjectName("hostList")
        self.horizontalLayout_2.addWidget(self.hostList)
        self.verticalLayout_2 = QtGui.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.hostAddButton = QtGui.QPushButton(self.layoutWidget)
        self.hostAddButton.setObjectName("hostAddButton")
        self.verticalLayout_2.addWidget(self.hostAddButton)
        self.hostEditButton = QtGui.QPushButton(self.layoutWidget)
        self.hostEditButton.setObjectName("hostEditButton")
        self.verticalLayout_2.addWidget(self.hostEditButton)
        self.hostDeleteButton = QtGui.QPushButton(self.layoutWidget)
        self.hostDeleteButton.setObjectName("hostDeleteButton")
        self.verticalLayout_2.addWidget(self.hostDeleteButton)
        spacerItem = QtGui.QSpacerItem(20,40,QtGui.QSizePolicy.Minimum,QtGui.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.tabWidget.addTab(self.hosts,"")
        self.logging = QtGui.QWidget()
        self.logging.setObjectName("logging")
        self.gridLayout_2 = QtGui.QGridLayout(self.logging)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.logTrafficCheckBox = QtGui.QCheckBox(self.logging)
        self.logTrafficCheckBox.setObjectName("logTrafficCheckBox")
        self.gridLayout_2.addWidget(self.logTrafficCheckBox,0,0,1,1)
        spacerItem1 = QtGui.QSpacerItem(20,164,QtGui.QSizePolicy.Minimum,QtGui.QSizePolicy.Expanding)
        self.gridLayout_2.addItem(spacerItem1,1,0,1,1)
        self.tabWidget.addTab(self.logging,"")
        self.view = QtGui.QWidget()
        self.view.setObjectName("view")
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.view)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.truncateUuidsCheckBox = QtGui.QCheckBox(self.view)
        self.truncateUuidsCheckBox.setObjectName("truncateUuidsCheckBox")
        self.verticalLayout_3.addWidget(self.truncateUuidsCheckBox)
        spacerItem2 = QtGui.QSpacerItem(20,164,QtGui.QSizePolicy.Minimum,QtGui.QSizePolicy.Expanding)
        self.verticalLayout_3.addItem(spacerItem2)
        self.tabWidget.addTab(self.view,"")
        self.verticalLayout.addWidget(self.tabWidget)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem3 = QtGui.QSpacerItem(40,20,QtGui.QSizePolicy.Expanding,QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem3)
        self.buttonBox = QtGui.QDialogButtonBox(ConfigWindow)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Apply|QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.horizontalLayout.addWidget(self.buttonBox)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.gridLayout.addLayout(self.verticalLayout,0,0,1,1)

        self.retranslateUi(ConfigWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(ConfigWindow)
        ConfigWindow.setTabOrder(self.hostList,self.hostAddButton)
        ConfigWindow.setTabOrder(self.hostAddButton,self.hostEditButton)
        ConfigWindow.setTabOrder(self.hostEditButton,self.hostDeleteButton)
        ConfigWindow.setTabOrder(self.hostDeleteButton,self.buttonBox)
        ConfigWindow.setTabOrder(self.buttonBox,self.tabWidget)

    def retranslateUi(self, ConfigWindow):
        ConfigWindow.setWindowTitle(QtGui.QApplication.translate("ConfigWindow", "OVSDB Monitor Configuration", None, QtGui.QApplication.UnicodeUTF8))
        self.hostAddButton.setText(QtGui.QApplication.translate("ConfigWindow", "Add", None, QtGui.QApplication.UnicodeUTF8))
        self.hostEditButton.setText(QtGui.QApplication.translate("ConfigWindow", "Edit", None, QtGui.QApplication.UnicodeUTF8))
        self.hostDeleteButton.setText(QtGui.QApplication.translate("ConfigWindow", "Delete", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.hosts), QtGui.QApplication.translate("ConfigWindow", "Hosts", None, QtGui.QApplication.UnicodeUTF8))
        self.logTrafficCheckBox.setToolTip(QtGui.QApplication.translate("ConfigWindow", "Whether to log traffic exchanges in the log window", None, QtGui.QApplication.UnicodeUTF8))
        self.logTrafficCheckBox.setText(QtGui.QApplication.translate("ConfigWindow", "Log traffic", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.logging), QtGui.QApplication.translate("ConfigWindow", "Logging", None, QtGui.QApplication.UnicodeUTF8))
        self.truncateUuidsCheckBox.setToolTip(QtGui.QApplication.translate("ConfigWindow", "Replaces UUIDs with a shorter string of the first few characters.  The tooltip still contains the full value", None, QtGui.QApplication.UnicodeUTF8))
        self.truncateUuidsCheckBox.setText(QtGui.QApplication.translate("ConfigWindow", "Truncate UUIDs", None, QtGui.QApplication.UnicodeUTF8))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.view), QtGui.QApplication.translate("ConfigWindow", "View", None, QtGui.QApplication.UnicodeUTF8))

