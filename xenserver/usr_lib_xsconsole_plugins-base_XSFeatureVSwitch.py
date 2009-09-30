# Copyright (c) Citrix Systems 2008. All rights reserved.
# xsconsole is proprietary software.
#
# Xen, the Xen logo, XenCenter, XenMotion are trademarks or registered
# trademarks of Citrix Systems, Inc., in the United States and other
# countries.

# Copyright (c) 2009 Nicira Networks.

from XSConsoleLog import *

import os
import socket
import subprocess

cfg_mod="/usr/bin/ovs-cfg-mod"
vswitchd_cfg_filename="/etc/ovs-vswitchd.conf"

if __name__ == "__main__":
    raise Exception("This script is a plugin for xsconsole and cannot run independently")

from XSConsoleStandard import *

class VSwitchService:
    service = {}

    def __init__(self, name, processname=None):
        self.name = name
        self.processname = processname
        if self.processname == None:
            self.processname = name

    def version(self):
        try:
            output = ShellPipe(["service", self.name, "version"]).Stdout()
        except StandardError, e:
            XSLogError("vswitch version retrieval error: " + str(e))
            return "<unknown>"
        for line in output:
            if self.processname in line:
                return line.split()[-1]
        return "<unknown>"

    def status(self):
        try:
            output = ShellPipe(["service", self.name, "status"]).Stdout()
        except StandardError, e:
            XSLogError("vswitch status retrieval error: " + str(e))
            return "<unknown>"
        if len(output) == 0:
            return "<unknown>"
        for line in output:
            if self.processname not in line:
                continue
            elif "running" in line:
                return "Running"
            elif "stop" in line:
                return "Stopped"
            else:
                return "<unknown>"
        return "<unknown>"

    def restart(self):
        try:
            ShellPipe(["service", self.name, "restart"]).Call()
        except StandardError, e:
            XSLogError("vswitch restart error: " + str(e))

    @classmethod
    def Inst(cls, name, processname=None):
        key = name
        if processname != None:
            key = key + "-" + processname
        if name not in cls.service:
            cls.service[key] = VSwitchService(name, processname)
        return cls.service[key]

class VSwitchConfig:

    @staticmethod
    def Get(key):
        try:
            output = ShellPipe([cfg_mod, "-vANY:console:emer", "-F", 
                    vswitchd_cfg_filename, "-q", key]).Stdout()
        except StandardError, e:
            XSLogError("config retrieval error: " + str(e))
            return "<unknown>"

        if len(output) == 0:
            output = ""
        else:
            output = output[0].strip()
        return output


class VSwitchControllerDialogue(Dialogue):
    def __init__(self):
        Dialogue.__init__(self)
        data=Data.Inst()

        self.hostsInPool = 0
        self.hostsUpdated = 0
        pool = data.GetPoolForThisHost()
        if pool is not None:
            self.controller = pool.get("other_config", {}).get("vSwitchController", "")
        else:
            self.controller = ""

        choiceDefs = [
            ChoiceDef(Lang("Set pool-wide controller"),
                      lambda: self.getController()),
            ChoiceDef(Lang("Delete pool-wide controller"),
                      lambda: self.deleteController()),
            ChoiceDef(Lang("Resync server controller config"),
                      lambda: self.syncController()),
#             ChoiceDef(Lang("Restart ovs-vswitchd"),
#                       lambda: self.restartService("vswitch")),
#             ChoiceDef(Lang("Restart ovs-brcompatd"),
#                       lambda: self.restartService("vswitch-brcompatd"))
            ]
        self.menu = Menu(self, None, Lang("Configure vSwitch"), choiceDefs)

        self.ChangeState("INITIAL")

    def BuildPane(self):
        pane = self.NewPane(DialoguePane(self.parent))
        pane.TitleSet(Lang("Configure vSwitch"))
        pane.AddBox()

    def ChangeState(self, inState):
        self.state = inState
        self.BuildPane()
        self.UpdateFields()

    def UpdateFields(self):
        self.Pane().ResetPosition()
        getattr(self, "UpdateFields" + self.state)() # Dispatch method named 'UpdateFields'+self.state

    def UpdateFieldsINITIAL(self):
        pane = self.Pane()
        pane.AddTitleField(Lang("Select an action"))
        pane.AddMenuField(self.menu)
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )

    def UpdateFieldsGETCONTROLLER(self):
        pane = self.Pane()
        pane.ResetFields()

        pane.AddTitleField(Lang("Enter IP address of controller"))
        pane.AddInputField(Lang("Address", 16), self.controller, "address")
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Exit") } )
        if pane.CurrentInput() is None:
            pane.InputIndexSet(0)

    def HandleKey(self, inKey):
        handled = False
        if hasattr(self, "HandleKey" + self.state):
            handled = getattr(self, "HandleKey" + self.state)(inKey)
        if not handled and inKey == 'KEY_ESCAPE':
            Layout.Inst().PopDialogue()
            handled = True
        return handled

    def HandleKeyINITIAL(self, inKey):
        return self.menu.HandleKey(inKey)

    def HandleKeyGETCONTROLLER(self, inKey):
        pane = self.Pane()
        if pane.CurrentInput() is None:
            pane.InputIndexSet(0)
        if inKey == 'KEY_ENTER':
            inputValues = pane.GetFieldValues()
            self.controller = inputValues['address']
            Layout.Inst().PopDialogue()

            # Make sure the controller is specified as a valid dotted quad
            try:
                socket.inet_aton(self.controller)
            except socket.error:
                Layout.Inst().PushDialogue(InfoDialogue(Lang("Please enter in dotted quad format")))
                return True

            Layout.Inst().TransientBanner(Lang("Setting controller..."))
            try:
                self.SetController(self.controller)
                Layout.Inst().PushDialogue(InfoDialogue(Lang("Setting controller successful")))
            except Exception, e:
                Layout.Inst().PushDialogue(InfoDialogue(Lang("Setting controller failed")))

            self.ChangeState("INITIAL")
            return True
        else:
            return pane.CurrentInput().HandleKey(inKey)

    def restartService(self, name):
        s = VSwitchService.Inst(name)
        s.restart()
        Layout.Inst().PopDialogue()

    def getController(self):
        self.ChangeState("GETCONTROLLER")
        self.Pane().InputIndexSet(0)

    def deleteController(self):
        self.controller = ""
        Layout.Inst().PopDialogue()
        Layout.Inst().TransientBanner(Lang("Deleting controller..."))
        try:
            self.SetController(None)
            Layout.Inst().PushDialogue(InfoDialogue(Lang("Controller deletion successful")))
        except Exception, e:
            Layout.Inst().PushDialogue(InfoDialogue(Lang("Controller deletion failed")))

    def syncController(self):
        Layout.Inst().PopDialogue()
        Layout.Inst().TransientBanner(Lang("Resyncing controller setting..."))
        try:
            Task.Sync(lambda s: self._updateThisServer(s))
            Layout.Inst().PushDialogue(InfoDialogue(Lang("Resyncing controller config successful")))
        except Exception, e:
            Layout.Inst().PushDialogue(InfoDialogue(Lang("Resyncing controller config failed")))

    def SetController(self, ip):
        self.hostsInPool = 0
        self.hostsUpdated = 0
        Task.Sync(lambda s: self._modifyPoolConfig(s, "vSwitchController", ip))
        # Should be done asynchronously, maybe with an external script?
        Task.Sync(lambda s: self._updateActiveServers(s))

    def _modifyPoolConfig(self, session, key, value):
        """Modify pool configuration.

        If value == None then delete key, otherwise set key to value."""
        pools = session.xenapi.pool.get_all()
        # We assume there is only ever one pool...
        if len(pools) == 0:
            log.error("No pool for host.")
            raise XenAPIPlugin.Failure("NO_POOL_FOR_HOST", [])
        if len(pools) > 1:
            log.error("More than one pool for host.")
            raise XenAPIPlugin.Failure("MORE_THAN_ONE_POOL_FOR_HOST", [])
        session.xenapi.pool.remove_from_other_config(pools[0], key)
        if value != None:
            session.xenapi.pool.add_to_other_config(pools[0], key, value)
        Data.Inst().Update()

    def _updateActiveServers(self, session):
        hosts = session.xenapi.host.get_all()
        self.hostsUpdated = 0
        self.hostsInPool = len(hosts)
        self.UpdateFields()
        for host in hosts:
            Layout.Inst().TransientBanner("Updating host %d out of %d" 
                    % (self.hostsUpdated + 1, self.hostsInPool))
            session.xenapi.host.call_plugin(host, "vswitch-cfg-update", "update", {})
            self.hostsUpdated = self.hostsUpdated + 1

    def _updateThisServer(self, session):
        data = Data.Inst()
        host = data.host.opaqueref()
        session.xenapi.host.call_plugin(host, "vswitch-cfg-update", "update", {})


class XSFeatureVSwitch:

    @classmethod
    def StatusUpdateHandler(cls, inPane):
        data = Data.Inst()

        inPane.AddTitleField(Lang("vSwitch"))

        inPane.NewLine()

        inPane.AddStatusField(Lang("Version", 20),
                              VSwitchService.Inst("vswitch", "ovs-vswitchd").version())

        inPane.NewLine()

        pool = data.GetPoolForThisHost()
        if pool is not None:
            dbController = pool.get("other_config", {}).get("vSwitchController", "")
        else:
            dbController = ""

        if dbController == "":
            dbController = Lang("<None>")
        inPane.AddStatusField(Lang("Controller (config)", 20), dbController)
        controller = VSwitchConfig.Get("mgmt.controller")
        if controller == "":
            controller = Lang("<None>")
        elif controller[0:4] == "ssl:":
            controller = controller[4:]
        inPane.AddStatusField(Lang("Controller (in-use)", 20), controller)

        inPane.NewLine()
        inPane.AddStatusField(Lang("ovs-vswitchd status", 20),
                              VSwitchService.Inst("vswitch", "ovs-vswitchd").status())
        inPane.AddStatusField(Lang("ovs-brcompatd status", 20),
                              VSwitchService.Inst("vswitch", "ovs-brcompatd").status())

        inPane.AddKeyHelpField( {
            Lang("<Enter>") : Lang("Reconfigure"),
            Lang("<F5>") : Lang("Refresh")
        })

    @classmethod
    def ActivateHandler(cls):
        DialogueUtils.AuthenticatedOnly(lambda: Layout.Inst().PushDialogue(VSwitchControllerDialogue()))

    def Register(self):
        Importer.RegisterNamedPlugIn(
            self,
            'VSwitch', # Key of this plugin for replacement, etc.
            {
                'menuname' : 'MENU_NETWORK',
                'menupriority' : 800,
                'menutext' : Lang('vSwitch') ,
                'statusupdatehandler' : self.StatusUpdateHandler,
                'activatehandler' : self.ActivateHandler
            }
        )

# Register this plugin when module is imported
XSFeatureVSwitch().Register()
