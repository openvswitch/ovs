ovsdbmonitor_pyfiles = \
	ovsdb/ovsdbmonitor/OVEApp.py \
	ovsdb/ovsdbmonitor/OVECommonWindow.py \
	ovsdb/ovsdbmonitor/OVEConfig.py \
	ovsdb/ovsdbmonitor/OVEConfigWindow.py \
	ovsdb/ovsdbmonitor/OVEFetch.py \
	ovsdb/ovsdbmonitor/OVEFlowWindow.py \
	ovsdb/ovsdbmonitor/OVEHostWindow.py \
	ovsdb/ovsdbmonitor/OVELogWindow.py \
	ovsdb/ovsdbmonitor/OVELogger.py \
	ovsdb/ovsdbmonitor/OVEMainWindow.py \
	ovsdb/ovsdbmonitor/OVEStandard.py \
	ovsdb/ovsdbmonitor/OVEUtil.py \
	ovsdb/ovsdbmonitor/Ui_ConfigWindow.py \
	ovsdb/ovsdbmonitor/Ui_FlowWindow.py \
	ovsdb/ovsdbmonitor/Ui_HostWindow.py \
	ovsdb/ovsdbmonitor/Ui_LogWindow.py \
	ovsdb/ovsdbmonitor/Ui_MainWindow.py \
	ovsdb/ovsdbmonitor/qt4reactor.py
EXTRA_DIST += \
	$(ovsdbmonitor_pyfiles) \
	ovsdb/ovsdbmonitor/COPYING \
	ovsdb/ovsdbmonitor/ConfigWindow.ui \
	ovsdb/ovsdbmonitor/FlowWindow.ui \
	ovsdb/ovsdbmonitor/HostWindow.ui \
	ovsdb/ovsdbmonitor/LogWindow.ui \
	ovsdb/ovsdbmonitor/MainWindow.ui \
	ovsdb/ovsdbmonitor/ovsdbmonitor.in \
	ovsdb/ovsdbmonitor/ovsdbmonitor.desktop
MAN_ROOTS += ovsdb/ovsdbmonitor/ovsdbmonitor.1

ovsdbmonitordir = ${datadir}/ovsdbmonitor
desktopdir = ${datadir}/applications
if BUILD_OVSDBMONITOR
noinst_SCRIPTS += ovsdb/ovsdbmonitor/ovsdbmonitor
ovsdbmonitor_DATA = $(ovsdbmonitor_pyfiles)
desktop_DATA = ovsdb/ovsdbmonitor/ovsdbmonitor.desktop
install-exec-hook:
	sed -e '/NOINSTALL/d' < ovsdb/ovsdbmonitor/ovsdbmonitor > ovsdb/ovsdbmonitor/ovsdbmonitor.tmp
	chmod +x ovsdb/ovsdbmonitor/ovsdbmonitor.tmp
	$(INSTALL_PROGRAM) ovsdb/ovsdbmonitor/ovsdbmonitor.tmp $(DESTDIR)$(bindir)/ovsdbmonitor
	rm ovsdb/ovsdbmonitor/ovsdbmonitor.tmp
DISTCLEANFILES += \
	ovsdb/ovsdbmonitor/ovsdbmonitor \
	ovsdb/ovsdbmonitor/ovsdbmonitor.tmp
man_MANS += ovsdb/ovsdbmonitor/ovsdbmonitor.1
endif

UNINSTALL_LOCAL += ovsdbmonitor-uninstall-local
ovsdbmonitor-uninstall-local:
	rm -f $(DESTDIR)$(bindir)/ovsdbmonitor

SUFFIXES += .ui .py
.ui.py:
	$(PYUIC4) $< | sed 's/from PyQt4 import QtCore, QtGui/\
try:\
    from OVEStandard import globalForcePySide\
    if globalForcePySide:\
        raise Exception()\
    from PyQt4 import QtCore, QtGui\
except:\
    from PySide import QtCore, QtGui/' > $@
