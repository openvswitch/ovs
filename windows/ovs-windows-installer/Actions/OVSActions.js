/*
Copyright 2015 Cloudbase Solutions Srl
All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License"); you may
   not use this file except in compliance with the License. You may obtain
   a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
   License for the specific language governing permissions and limitations
   under the License.
*/

// http://msdn.microsoft.com/en-us/library/sfw6660x(VS.85).aspx
var Buttons =
{
    OkOnly: 0,
    OkCancel: 1,
    AbortRetryIgnore: 2,
    YesNoCancel: 3
};

var Icons =
{
    Critical: 16,
    Question: 32,
    Exclamation: 48,
    Information: 64
}

var MsgKind =
{
    Error: 0x01000000,
    Warning: 0x02000000,
    User: 0x03000000,
    Log: 0x04000000
};

// http://msdn.microsoft.com/en-us/library/aa371254(VS.85).aspx
var MsiActionStatus =
{
    None: 0,
    Ok: 1, // success
    Cancel: 2,
    Abort: 3,
    Retry: 4, // aka suspend?
    Ignore: 5  // skip remaining actions; this is not an error.
};

var ServiceStartAction = {
    Stop: "Stop",
    Start: "Start",
    Restart: "Restart"
};

var ServiceStartMode = {
    Boot: "Boot",
    System: "System",
    Auto: "Auto",
    Manual: "Manual",
    Disabled: "Disabled"
};

function throwException(num, msg) {
    throw {
        number: num,
        message: msg
    };
}

function decimalToHexString(number) {
    if (number < 0)
        number = 0xFFFFFFFF + number + 1;
    return number.toString(16).toUpperCase();
}

function logMessage(msg) {
    var record = Session.Installer.CreateRecord(0);
    record.StringData(0) = "CustomActions: " + msg;
    Session.Message(MsgKind.Log, record);
}

function logMessageEx(msg, type) {
    var record = Session.Installer.CreateRecord(0);
    record.StringData(0) = msg;
    Session.Message(type, record);
}

function logException(exc) {
    var record = Session.Installer.CreateRecord(0);
    record.StringData(0) = exc.message == "" ? "An exception occurred: 0x" + decimalToHexString(exc.number) : exc.message;
    Session.Message(MsgKind.Error + Icons.Critical + Buttons.OkOnly, record);

    // Log the full exception as well
    record.StringData(0) = "CustomAction exception details: 0x" + decimalToHexString(exc.number) + " : " + exc.message;
    Session.Message(MsgKind.Log, record);
}

function runCommand(cmd, expectedReturnValue, envVars, windowStyle, waitOnReturn, workingDir) {
    var shell = new ActiveXObject("WScript.Shell");
    logMessage("Running command: " + cmd);

    if (envVars) {
        var env = shell.Environment("Process");
        for (var k in envVars)
            env(k) = envVars[k];
    }

    if (typeof windowStyle == 'undefined')
        windowStyle = 0;

    if (typeof waitOnReturn == 'undefined')
        waitOnReturn = true;

    if (typeof workingDir == 'undefined')
        workingDir = null;

    if (workingDir) {
        shell.CurrentDirectory = workingDir;
    }

    var retVal = shell.run(cmd, windowStyle, waitOnReturn);

    if (waitOnReturn && expectedReturnValue != undefined && expectedReturnValue != null && retVal != expectedReturnValue)
        throwException(-1, "Command failed. Return value: " + retVal.toString());

    logMessage("Command completed. Return value: " + retVal);

    return retVal;
}

function getWmiCimV2Svc() {
    return GetObject("winmgmts:\\\\.\\root\\cimv2");
}

function getSafeArray(jsArr) {
    var dict = new ActiveXObject("Scripting.Dictionary");
    for (var i = 0; i < jsArr.length; i++)
        dict.add(i, jsArr[i]);
    return dict.Items();
}

function invokeWMIMethod(svc, methodName, inParamsValues, wmiSvc, jobOutParamName) {
    logMessage("Invoking " + methodName);

    var inParams = null;
    if (inParamsValues) {
        for (var k in inParamsValues) {
            if (!inParams)
                inParams = svc.Methods_(methodName).InParameters.SpawnInstance_();
            var val = inParamsValues[k];
            if (val instanceof Array)
                inParams[k] = getSafeArray(val);
            else
                inParams[k] = val;
        }
    }

    var outParams = svc.ExecMethod_(methodName, inParams);
    if (outParams.ReturnValue == 4096) {
        var job = wmiSvc.Get(outParams[jobOutParamName]);
        waitForJob(wmiSvc, job);
    }
    else if (outParams.ReturnValue != 0)
        throwException(-1, methodName + " failed. Return value: " + outParams.ReturnValue.toString());

    return outParams;
}

function sleep(interval) {
    // WScript.Sleep is not supported in MSI's WSH. Here's a workaround for the moment.

    // interval is ignored
    var numPings = 2;
    cmd = "ping -n " + numPings + " 127.0.0.1";

    var shell = new ActiveXObject("WScript.Shell");
    shell.run(cmd, 0, true);
}

function getService(serviceName) {
    var wmiSvc = getWmiCimV2Svc();
    return wmiSvc.ExecQuery("SELECT * FROM Win32_Service WHERE Name='" + serviceName + "'").ItemIndex(0);
}

function changeService(serviceName, startMode, startAction) {
    var svc = getService(serviceName);

    if ((startAction == ServiceStartAction.Stop || startAction == ServiceStartAction.Restart) && svc.Started)
        invokeWMIMethod(svc, "StopService");

    if (startMode && svc.StartMode != startMode)
        invokeWMIMethod(svc, "ChangeStartMode",
                {
                    "StartMode": (startMode == ServiceStartMode.Auto ? "Automatic" : startMode)
                });

    if (startAction == ServiceStartAction.Restart && svc.Started) {
        var wmiSvc = getWmiCimV2Svc();
        do {
            sleep(200);
            svc = wmiSvc.Get(svc.Path_);
        } while (svc.Started);
    }

    if ((startAction == ServiceStartAction.Start || startAction == ServiceStartAction.Restart) && !svc.Started)
        invokeWMIMethod(svc, "StartService");
}

function runCommandAction() {
    var exceptionMsg = null;

    try {
        var data = Session.Property("CustomActionData").split('|');
        var i = 0;
        var cmd = data[i++];
        var expectedRetValue = data.length > i ? data[i++] : 0;
        var exceptionMsg = data.length > i ? data[i++] : null;
        var workingDir = data.length > i ? data[i++] : null;

        runCommand(cmd, expectedRetValue, null, 0, true, workingDir);
        return MsiActionStatus.Ok;
    }
    catch (ex) {
        if (exceptionMsg) {
            logMessageEx(exceptionMsg, MsgKind.Error + Icons.Critical + Buttons.OkOnly);
            // log also the original exception
            logMessage(ex.message);
        }
        else
            logException(ex);

        return MsiActionStatus.Abort;
    }
}

function changeServiceAction() {
    try {
        var data = Session.Property("CustomActionData").split('|');
        var serviceName = data[0];
        var startMode = data[1];
        var startAction = data[2];

        logMessage("Changing service " + serviceName + ", startMode: " + startMode + ", startAction: " + startAction);

        changeService(serviceName, startMode, startAction);

        return MsiActionStatus.Ok;
    }
    catch (ex) {
        logMessage(ex.message);
        return MsiActionStatus.Abort;
    }
}