# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'HostWindow.ui'
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

class Ui_HostWindow(object):
    def setupUi(self, HostWindow):
        HostWindow.setObjectName("HostWindow")
        HostWindow.setWindowModality(QtCore.Qt.WindowModal)
        HostWindow.resize(400,300)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum,QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(HostWindow.sizePolicy().hasHeightForWidth())
        HostWindow.setSizePolicy(sizePolicy)
        self.gridLayout_2 = QtGui.QGridLayout(HostWindow)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtGui.QLabel(HostWindow)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label,0,0,1,1)
        self.hostAddressEdit = QtGui.QLineEdit(HostWindow)
        self.hostAddressEdit.setMinimumSize(QtCore.QSize(256,0))
        self.hostAddressEdit.setObjectName("hostAddressEdit")
        self.gridLayout.addWidget(self.hostAddressEdit,0,1,1,1)
        self.label_2 = QtGui.QLabel(HostWindow)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2,1,0,1,1)
        self.hostPasswordEdit = QtGui.QLineEdit(HostWindow)
        self.hostPasswordEdit.setMinimumSize(QtCore.QSize(256,0))
        self.hostPasswordEdit.setEchoMode(QtGui.QLineEdit.Password)
        self.hostPasswordEdit.setObjectName("hostPasswordEdit")
        self.gridLayout.addWidget(self.hostPasswordEdit,1,1,1,1)
        self.label_3 = QtGui.QLabel(HostWindow)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3,2,0,1,1)
        self.hostConnectTarget = QtGui.QLineEdit(HostWindow)
        self.hostConnectTarget.setMinimumSize(QtCore.QSize(256,0))
        self.hostConnectTarget.setObjectName("hostConnectTarget")
        self.gridLayout.addWidget(self.hostConnectTarget,2,1,1,1)
        self.gridLayout_2.addLayout(self.gridLayout,0,0,1,1)
        self.buttonBox = QtGui.QDialogButtonBox(HostWindow)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout_2.addWidget(self.buttonBox,1,0,1,1)
        self.label.setBuddy(self.hostAddressEdit)
        self.label_2.setBuddy(self.hostPasswordEdit)
        self.label_3.setBuddy(self.hostConnectTarget)

        self.retranslateUi(HostWindow)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("accepted()"),HostWindow.accept)
        QtCore.QObject.connect(self.buttonBox,QtCore.SIGNAL("rejected()"),HostWindow.reject)
        QtCore.QMetaObject.connectSlotsByName(HostWindow)
        HostWindow.setTabOrder(self.hostAddressEdit,self.hostPasswordEdit)
        HostWindow.setTabOrder(self.hostPasswordEdit,self.buttonBox)

    def retranslateUi(self, HostWindow):
        HostWindow.setWindowTitle(QtGui.QApplication.translate("HostWindow", "Host Properties", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("HostWindow", "Host name or IP", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("HostWindow", "SSH Password", None, QtGui.QApplication.UnicodeUTF8))
        self.label_3.setText(QtGui.QApplication.translate("HostWindow", "Connect target", None, QtGui.QApplication.UnicodeUTF8))

