# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'LogWindow.ui'
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

class Ui_LogWindow(object):
    def setupUi(self, LogWindow):
        LogWindow.setObjectName("LogWindow")
        LogWindow.resize(735,558)
        self.gridLayout = QtGui.QGridLayout(LogWindow)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout = QtGui.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.textBrowser = QtGui.QTextBrowser(LogWindow)
        self.textBrowser.setObjectName("textBrowser")
        self.verticalLayout.addWidget(self.textBrowser)
        self.buttonBox = QtGui.QDialogButtonBox(LogWindow)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Close|QtGui.QDialogButtonBox.Reset)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)
        self.gridLayout.addLayout(self.verticalLayout,0,0,1,1)

        self.retranslateUi(LogWindow)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("accepted()"),LogWindow.accept)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("rejected()"),LogWindow.reject)
        QtCore.QMetaObject.connectSlotsByName(LogWindow)

    def retranslateUi(self, LogWindow):
        LogWindow.setWindowTitle(QtGui.QApplication.translate("LogWindow", "OVSDB Monitor Log", None, QtGui.QApplication.UnicodeUTF8))

