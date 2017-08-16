# Copyright (c) 2016 Cloudbase Solutions Srl
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

import sys

if sys.platform != 'win32':
    raise Exception("Intended to use only on Windows")
else:
    import pywintypes
    import win32con
    import win32event
    import win32file
    import win32pipe
    import win32security
    import winerror


def close_handle(handle, logger=None):
    try:
        win32file.CloseHandle(handle)
        return None
    except pywintypes.error as e:
        if logger is not None:
            logger("failed to close handle: %s" % e.strerror)
        return e.winerror


def windows_create_pipe(sAttrs=-1, nSize=None):
    # Default values if parameters are not passed
    if sAttrs == -1:
        sAttrs = win32security.SECURITY_ATTRIBUTES()
        sAttrs.bInheritHandle = 1
    if nSize is None:
        # If this parameter is zero, the system uses the default buffer size.
        nSize = 0

    try:
        (read_pipe, write_pipe) = win32pipe.CreatePipe(sAttrs, nSize)
    except pywintypes.error:
        raise

    return (read_pipe, write_pipe)


def windows_read_pipe(fd, length):
    try:
        (error, data) = win32file.ReadFile(fd, length)
        return error, data
    except pywintypes.error as e:
        return e.winerror, ""


def create_file(filename, desiredAccess=None, shareMode=None, attributes=-1,
                CreationDisposition=None, flagsAndAttributes=None,
                hTemplateFile=-1):
    # Default values if parameters are not passed
    if desiredAccess is None:
        desiredAccess = win32file.GENERIC_READ | win32file.GENERIC_WRITE
    if shareMode is None:
        shareMode = 0
    if attributes == -1:
        # attributes can be None
        attributes = None
    if CreationDisposition is None:
        CreationDisposition = win32file.OPEN_EXISTING
    if flagsAndAttributes is None:
        flagsAndAttributes = (win32file.FILE_ATTRIBUTE_NORMAL |
                              win32file.FILE_FLAG_OVERLAPPED |
                              win32file.FILE_FLAG_NO_BUFFERING)
    if hTemplateFile == -1:
        hTemplateFile = None

    try:
        npipe = win32file.CreateFile(filename,
                                     desiredAccess,
                                     shareMode,
                                     attributes,
                                     CreationDisposition,
                                     flagsAndAttributes,
                                     hTemplateFile)
    except pywintypes.error:
        raise
    return npipe


def write_file(handle, data, overlapped=None):
    try:
        (errCode, nBytesWritten) = win32file.WriteFile(handle,
                                                       data,
                                                       overlapped)
        # Note: win32file.WriteFile doesn't throw an exception
        # in case it receives ERROR_IO_PENDING.
        return (errCode, nBytesWritten)
    except pywintypes.error as e:
        return (e.winerror, 0)


def read_file(handle, bufsize, overlapped=None):
    try:
        # Note: win32file.ReadFile doesn't throw an exception
        # in case it receives ERROR_IO_PENDING.
        (errCode, read_buffer) = win32file.ReadFile(
            handle, bufsize, overlapped)
        return (errCode, read_buffer)
    except pywintypes.error as e:
        return (e.winerror, "")


def create_named_pipe(pipename, openMode=None, pipeMode=None,
                      nMaxInstances=None, nOutBufferSize=None,
                      nInBufferSize=None, nDefaultTimeOut=None,
                      saAttr=-1):
    # Default values if parameters are not passed
    if openMode is None:
        openMode = win32con.PIPE_ACCESS_DUPLEX | win32con.FILE_FLAG_OVERLAPPED
    if pipeMode is None:
        pipeMode = (win32con.PIPE_TYPE_MESSAGE |
                    win32con.PIPE_READMODE_BYTE |
                    win32con.PIPE_WAIT)
    if nMaxInstances is None:
        nMaxInstances = 64
    if nOutBufferSize is None:
        nOutBufferSize = 65000
    if nInBufferSize is None:
        nInBufferSize = 65000
    if nDefaultTimeOut is None:
        nDefaultTimeOut = 0
    if saAttr == -1:
        # saAttr can be None
        saAttr = win32security.SECURITY_ATTRIBUTES()
        saAttr.bInheritHandle = 1

    try:
        npipe = win32pipe.CreateNamedPipe(pipename,
                                          openMode,
                                          pipeMode,
                                          nMaxInstances,
                                          nOutBufferSize,
                                          nInBufferSize,
                                          nDefaultTimeOut,
                                          saAttr)

        if npipe == win32file.INVALID_HANDLE_VALUE:
            return None

        return npipe
    except pywintypes.error:
        return None


def set_pipe_mode(hPipe, mode=-1, maxCollectionCount=None,
                  collectDataTimeout=None):
    # Default values if parameters are not passed
    if mode == -1:
        mode = win32pipe.PIPE_READMODE_BYTE
    try:
        win32pipe.SetNamedPipeHandleState(
            hPipe, mode, maxCollectionCount, collectDataTimeout)
    except pywintypes.error:
        raise


def connect_named_pipe(pipe_handle, overlapped=None):
    try:
        # If the result of ConnectNamedPipe is ERROR_IO_PENDING or
        # ERROR_PIPE_CONNECTED, then this value is returned.
        # All other error values raise a win32 exception
        error = win32pipe.ConnectNamedPipe(pipe_handle, overlapped)
        return error
    except pywintypes.error as e:
        return e.winerror


def get_pipe_name(name):
    name = name.replace('/', '')
    name = name.replace('\\', '')
    name = "\\\\.\\pipe\\" + name
    return name


def get_overlapped_result(handle, overlapped=None, bWait=False):
    try:
        return win32file.GetOverlappedResult(handle, overlapped, bWait)
    except pywintypes.error:
        raise


def get_new_event(sa=None, bManualReset=True, bInitialState=True,
                  objectName=None):
    return win32event.CreateEvent(sa, bManualReset, bInitialState, objectName)


pipe_disconnected_errors = [winerror.ERROR_PIPE_NOT_CONNECTED,
                            winerror.ERROR_BAD_PIPE,
                            winerror.ERROR_NO_DATA,
                            winerror.ERROR_BROKEN_PIPE]
