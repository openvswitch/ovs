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
from OVELogger import *
import ovs.json

# This sequence installs the qt4reactor before twisted gets a chance to install its reactor
import qt4reactor
globalApp = QtGui.QApplication([])
qt4reactor.install()

try:
    from twisted.conch.ssh import transport, userauth, connection, common, keys, channel
    from twisted.internet import defer, protocol, reactor
    from twisted.application import reactors
except Exception, e:
    print('+++ Python Twisted Conch module is required\n')
    raise

class OVEFetchUserAuth(userauth.SSHUserAuthClient):
    def __init__(self, fetch, *params):
        userauth.SSHUserAuthClient.__init__(self, *params)
        self.fetch = fetch
        self.authFails = 0
    
    def getPassword(self):
        return defer.succeed(self.fetch.config()['password'])

    def ssh_USERAUTH_FAILURE(self, packet):
        if self.authFails > 0: # We normally get one so ignore.  Real failures send these repeatedly
            OVELog('Authentication failure for '+self.fetch.config()['address'])
        self.authFails += 1
        userauth.SSHUserAuthClient.ssh_USERAUTH_FAILURE(self, packet)

class OVEFetchConnection(connection.SSHConnection, QtCore.QObject):
    def __init__(self, fetch, *params):
        connection.SSHConnection.__init__(self, *params)
        QtCore.QObject.__init__(self)
        self.fetch = fetch
        self._channel = None
        self._oldChannels = []
        
    def serviceStarted(self):
        self.emit(QtCore.SIGNAL('connectionService(QObject)'), self)

    def serviceStopped(self):
        self.emit(QtCore.SIGNAL('connectionService(QObject)'), None)

    def execCommand(self, requester, ref, command, commandType):
        if self._channel is not None:
            # Don't delete old channels immediately in case they're e.g. going to time out with a failure
            self._oldChannels.append(self._channel)
            if len(self._oldChannels) > 90:
                # For 30 second timeouts at 1 second refresh interval and three windows open on a single host, need 90 channels
                del self._oldChannels[1]
        self._channel = OVECommandChannel(self.fetch, requester, ref, command, commandType, 2**16, 2**15, self)
        self.openChannel(self._channel)

    def connectionLost(self, reason):
        if self._channel is not None:
            self._channel.connectionLost(reason)

class OVEFetchTransport(transport.SSHClientTransport, QtCore.QObject):
    def __init__(self, fetch, *params):
        # There is no __init__ method for this class
        # transport.SSHClientTransport.__init__(self, *params)
        
        QtCore.QObject.__init__(self)
        self.fetch = fetch
        self._connection = None
        self.connect(self, QtCore.SIGNAL('channelFailure(QObject, int, QString, QString, QString)'), self.fetch.xon_channelFailure)
        
    def verifyHostKey(self, hostKey, fingerprint):
        return defer.succeed(1)

    def connectionSecure(self):
        self._connection = OVEFetchConnection(self.fetch)
        QtCore.QObject.connect(self._connection, QtCore.SIGNAL('connectionService(QObject)'), self.fetch.xon_connectionService)
        self.requestService(
            OVEFetchUserAuth(self.fetch, self.fetch.config().get('username', 'root'),
                self._connection))

    def connectionLost(self, reason):
        if self._connection is not None:
            self._connection.connectionLost(reason)

class OVEFetchWrapper:
    def __init__(self, contents):
        self.contents = contents

class OVECommandChannel(channel.SSHChannel, QtCore.QObject):
    name = 'session'
    MSEC_TIMEOUT=10000
    STATUS_CONNECTION_LOST = 100001
    STATUS_TIMEOUT = 100002
    END_MARKER='END-MARKER'
    END_MARKER_RE=re.compile(r'^END-MARKER$', re.MULTILINE)
    
    def __init__(self, fetch, requester, ref, command, commandType, *params):
        channel.SSHChannel.__init__(self, *params)
        QtCore.QObject.__init__(self)        
        self.fetch = fetch
        self.requester = requester
        self.ref = ref
        self.command = command
        self.commandType= commandType
        self._data = ''
        self._extData = ''
        self._jsonValues = None
        self._timerId = None
        self._status = None
        self.connect(self, QtCore.SIGNAL('channelData(QObject, int, QString)'), self.fetch.xon_channelData)
        self.connect(self, QtCore.SIGNAL('channelExtData(QObject, int, QString)'), self.fetch.xon_channelExtData)
        self.connect(self, QtCore.SIGNAL('channelSuccess(QObject, int, QString, QString, QVariant)'), self.fetch.xon_channelSuccess)
        self.connect(self, QtCore.SIGNAL('channelFailure(QObject, int, QString, QString, QString)'), self.fetch.xon_channelFailure)
        
    def openFailed(self, reason):
        if self._timerId is not None:
            self.killTimer(self._timerId)
        self.emit(QtCore.SIGNAL('channelFailure(QObject, int, QString, QString, QString)'), self.requester, self.ref,
            'Open failed:'+str(reason), '', '')

    def channelOpen(self, ignoredData):
        try:
            nsCommand = common.NS(str(self.command))
            self._timerId = self.startTimer(self.MSEC_TIMEOUT)
            self.conn.sendRequest(self, 'exec', nsCommand, wantReply=1)
        except Exception, e:
            self.emit(QtCore.SIGNAL('channelFailure(QObject, int, QString, QString, QString)'), self.requester, self.ref,
                'Open failed:'+str(e), self._data, self._extData)
            
    def dataReceived(self, data):
        self._data += data
        if OVEConfig.Inst().logTraffic:
            self.emit(QtCore.SIGNAL('channelData(QObject, int, QString)'), self.requester, self.ref, data)
        self.testIfDone()
        
    def extDataReceived(self, extData):
        self._extData += extData
        if OVEConfig.Inst().logTraffic:
            self.emit(QtCore.SIGNAL('channelExtData(QObject, int, QString)'), self.requester, self.ref, extData)

    def request_exit_status(self, data):
        # We can get the exit status before the data, so delay calling sendResult until we get both
        self._status = struct.unpack('>L', data)[0]
        self.testIfDone()
        
    def testIfDone(self):
        if self._status is not None:
            if self._status != 0:
                self.sendResult() # Failed, so send what we have
            elif len(self._data) > 0:
                # Status == success and we have some data
                if self.commandType == 'JSON':
                    try:
                        # Decode the JSON data, to confirm that we have all of the data
                        self._jsonValues = ovs.json.from_string(str(self._data)) # FIXME: Should handle unicode
                        self.sendResult()
                    except:
                        pass # Wait for more data
                elif self.commandType == 'framed':
                    match = self.END_MARKER_RE.search(self._data)
                    if match:
                        self._data = self._data[:match.start()] # Remove end marker
                        self.sendResult()
                else:
                    OVELog('Bad command type')

    def sendResult(self):
        if self._timerId is not None:
            self.killTimer(self._timerId)
        if self.commandType == 'JSON' and self._status == 0 and self._jsonValues is not None:
            self.emit(QtCore.SIGNAL('channelSuccess(QObject, int, QString, QString, QVariant)'), self.requester, self.ref, self._data, self._extData, QVariant(OVEFetchWrapper(self._jsonValues)))
        elif self.commandType != 'JSON' and self._status == 0:
            self.emit(QtCore.SIGNAL('channelSuccess(QObject, int, QString, QString, QVariant)'), self.requester, self.ref, self._data, self._extData, QVariant(None))
        else:
            self.emit(QtCore.SIGNAL('channelFailure(QObject, int, QString, QString, QString)'), self.requester, self.ref, 'Remote command failed (rc='+str(self._status)+')', self._data, self._extData)
        if self._status != self.STATUS_CONNECTION_LOST:
            try:
                self.loseConnection()
            except Exception, e:
                OVELog('OVECommandChannel.sendResult loseConnection error: '+str(e))

    def connectionLost(self, reason):
        self._extData += '+++ Connection lost'
        self._status = self.STATUS_CONNECTION_LOST
        self.sendResult()

    def timerEvent(self, event):
        if event.timerId() == self._timerId:
            self._extData += '+++ Timeout'
            self._status = self.STATUS_TIMEOUT
            self.sendResult()
        else:
            QtCore.QObject.timerEvent(self, event)

class OVEFetchEvent(QtCore.QEvent):
    TYPE = QtCore.QEvent.Type(QtCore.QEvent.registerEventType())
    def __init__(self, ref, data):
        QtCore.QEvent.__init__(self, self.TYPE)
        self.ref = ref
        self.data = data

class OVEFetchFailEvent(QtCore.QEvent):
    TYPE = QtCore.QEvent.Type(QtCore.QEvent.registerEventType())
    def __init__(self, ref, message):
        QtCore.QEvent.__init__(self, self.TYPE)
        self.ref = ref
        self.message = str(message)

class OVEFetch(QtCore.QObject):
    instances = {}
    SEC_TIMEOUT = 10.0
    
    def __init__(self, uuid):
        QtCore.QObject.__init__(self)
        self._hostUuid = uuid
        self._config = None
        self._transport = None
        self._connection = None
        self._commandQueue = []
        self._timerRef = 0
        self.refs = {}
        self.messages = {}
        self.values = {}
        self.connect(OVEConfig.Inst(), QtCore.SIGNAL("configUpdated()"), self.xon_configUpdated)
        
    @classmethod
    def Inst(cls, uuid):
        if uuid not in cls.instances:
            cls.instances[uuid] = OVEFetch(uuid)
        return cls.instances[uuid]

    @classmethod
    def startReactor(cls):
        reactor.runReturn()

    def xon_configUpdated(self):
        self._config = None
        self.resetTransport()
        
    def xon_connectionService(self, connection):
        self._connection = connection
        if self._connection is not None:
            OVELog('SSH connection to '+self.config()['address'] +' established')
            for command in self._commandQueue:
                # OVELog('Unqueueing '+str(command))
                self.execCommand2(*command)
            self._commandQueue = []

    def xon_channelData(self, requester, ref, data):
        if OVEConfig.Inst().logTraffic:
            OVELog('Channel data received: '+str(data))

    def xon_channelExtData(self, requester, ref, data):
        if OVEConfig.Inst().logTraffic:
            OVELog('+++ Channel extData (stderr) received: '+str(data))

    def xon_channelFailure(self, requester, ref, message, data, extData):
        if OVEConfig.Inst().logTraffic:
            OVELog('+++ Channel failure: '+str(message))
            OVELog("Closing SSH session due to failure")

        errMessage = message
        if len(data) > 0:
            errMessage += '\n+++ Failed command output: '+data
        if len(extData) > 0:
            errMessage += '\n+++ Failed command output (stderr): '+extData

        self.refs[requester] = ref # For PySide workaround
        self.messages[requester] = errMessage # For PySide workaround
        event = OVEFetchFailEvent(ref, errMessage)
        QtCore.QCoreApplication.postEvent(requester, event)
        self.resetTransport()
        
    def xon_channelSuccess(self, requester, ref, data, extData, jsonValueVariant):
        jsonValues = jsonValueVariant.toPyObject()
        if OVEConfig.Inst().logTraffic:
            OVELog('--- Channel success')
        try:
            if jsonValues is not None:
                values = jsonValues.contents
            else:
                values = str(data)

            self.refs[requester] = ref # For PySide workaround
            self.values[requester] = values # For PySide workaround
            event = OVEFetchEvent(ref, values)
            QtCore.QCoreApplication.postEvent(requester, event)
        except Exception, e:
            message = ('+++ Failed to decode JSON reply: '+str(e))
            if len(data) > 0: message += "\n++++++ Data (stdout): "+str(data)
            if len(extData) > 0: message += '\n++++++ Error (stderr): '+str(extData)
            self.refs[requester] = ref # For PySide workaround
            self.messages[requester] = message # For PySide workaround
            event = OVEFetchFailEvent(ref, message)
            QtCore.QCoreApplication.postEvent(requester, event)

    # Use for workaround only
    def snoopRef(self, requester):
        return self.refs.get(requester, None)

    # Use for workaround only
    def snoopValues(self, requester):
        return self.values.get(requester, None)

    # Use for workaround only
    def snoopMessage(self, requester):
        return self.messages.get(requester, None)

    def config(self):
        if self._config is None:
            self._config = OVEConfig.Inst().hostFromUuid(self._hostUuid)

        return self._config
    
    def resetTransport(self):
        if OVEConfig.Inst().logTraffic:
            OVELog('Transport reset for '+self.config()['address'])
        del self._connection
        del self._transport
        self._connection = None
        self._transport = None
        
    def transportErrback(self, failure, requester, ref, address):
        self._timerRef += 1 # Prevent timeout handling
        self.resetTransport()
        message = 'Failure connecting to '+address+': '+failure.getErrorMessage()
        self.refs[requester] = ref # For PySide workaround
        self.messages[requester] = message # For PySide workaround
        event = OVEFetchFailEvent(ref, message)
        QtCore.QCoreApplication.postEvent(requester, event)        
        
    def transportTimeout(self, timerRef, requester, ref, address):
        if self._timerRef == timerRef and self._transport is not None and self._connection is None:
            message = 'Connection attempt to ' +address+' timed out'
            self.refs[requester] = ref # For PySide workaround
            self.messages[requester] = message # For PySide workaround
            event = OVEFetchFailEvent(ref, message)
            QtCore.QCoreApplication.postEvent(requester, event)        
            self.resetTransport()

    def execCommand(self, requester, ref, command, commandType):
        if OVEConfig.Inst().logTraffic:
            hostName = (self.config() or {}).get('address', '<Address not set>')
            OVELog(str(QtCore.QTime.currentTime().toString())+' '+hostName+': Executing '+command)
        if self._transport is None:
            self._connection = None
            self._commandQueue.append((requester, ref, command, commandType))
            config = self.config()
            creator = protocol.ClientCreator(reactor, OVEFetchTransport, self)
            self._transport = creator.connectTCP(config['address'], config.get('port', 22), timeout = self.SEC_TIMEOUT)
            self._transport.addErrback(self.transportErrback, requester, ref, config['address'])
            self._timerRef += 1
            # Set this timer slightly longer than the twisted.conch timeout, as transportErrback can cancel
            # the timeout and prevent double handling
            # lambda timerRef = self._timerRef: takes a copy of self._timerRef
            QtCore.QTimer.singleShot(int((1+self.SEC_TIMEOUT) * 1000), lambda timerRef = self._timerRef: self.transportTimeout(timerRef, requester, ref, config['address']))
        else:
            self.execCommand2(requester, ref, command, commandType)

    def execCommand2(self, requester, ref, command, commandType):
        if self._connection is None:
            self._commandQueue.append((requester, ref, command, commandType))
        else:
            self._connection.execCommand(requester, ref, command, commandType)

    def getTable(self, requester, tableName, ref = QtCore.QObject()):
        command = '/usr/bin/ovsdb-client transact '+self.config()['connectTarget']+' \'["Open_vSwitch", {"op":"select","table":"'+tableName+'", "where":[]}]\''

        self.execCommand(requester, ref, command, 'JSON')
        
    def execCommandFramed(self, requester, ref, command):
        self.execCommand(requester, ref, command + ' && echo ' + OVECommandChannel.END_MARKER, 'framed')
