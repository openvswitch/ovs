/*
* Copyright 2014 Cloudbase Solutions Srl
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#pragma once

#include "precomp.h"

/*
 * These are error codes to be used by netlink transactional operations.
 * The error code is assigned to the "error" field (INT) of the NL_MSG_ERR
 * struct.
*/

typedef enum _NL_ERROR_
{
    NL_ERROR_SUCCESS = 0,
    /* The operation is not permitted */
    NL_ERROR_PERM = ((ULONG)-1),
    /* There is no such file or directory */
    NL_ERROR_NOENT = ((ULONG)-2),
    /* There is no such process */
    NL_ERROR_SRCH = ((ULONG)-3),
    /* An interrupted system call / interrupted function */
    NL_ERROR_INTR = ((ULONG)-4),
    /* An I/O error */
    NL_ERROR_IO = ((ULONG)-5),
    /* There is no such device or address */
    NL_ERROR_NXIO = ((ULONG)-6),
    /* The argument list is too long */
    NL_ERROR_2BIG = ((ULONG)-7),
    /* Executable file format error */
    NL_ERROR_NOEXEC = ((ULONG)-8),
    /* A bad file descriptor / number */
    NL_ERROR_BADF = ((ULONG)-9),
    /* Have no child processes */
    NL_ERROR_CHILD = ((ULONG)-10),
    /* resource unavailable => try again later */
    NL_ERROR_AGAIN = ((ULONG)-11),
    /* We're out of memory */
    NL_ERROR_NOMEM = ((ULONG)-12),
    /* Permission is denied */
    NL_ERROR_ACCES = ((ULONG)-13),
    /* A bad address */
    NL_ERROR_FAULT = ((ULONG)-14),

    /* The device or the resource is busy */
    NL_ERROR_BUSY = ((ULONG)-16),
    /* The file exists */
    NL_ERROR_EXIST = ((ULONG)-17),
    /* A cross-device link */
    NL_ERROR_XDEV = ((ULONG)-18),
    /* There is no such device */
    NL_ERROR_NODEV = ((ULONG)-19),
    /* It is not a directory, nor a symbolic link to a directory. */
    NL_ERROR_NOTDIR = ((ULONG)-20),
    /* This is a directory */
    NL_ERROR_ISDIR = ((ULONG)-21),
    /* An invalid argument */
    NL_ERROR_INVAL = ((ULONG)-22),
    /*
     * There are too many files open in system (i.e. no room for another file
     * descriptor)
     */
    NL_ERROR_NFILE = ((ULONG)-23),
    /* The file descriptor value is too large. */
    NL_ERROR_MFILE = ((ULONG)-24),
    /* And Inappropriate I/O control operation. Or, this is not a typewriter */
    NL_ERROR_NOTTY = ((ULONG)-25),

    /* The file is too large */
    NL_ERROR_FBIG = ((ULONG)-27),
    /* There is no space left on the device */
    NL_ERROR_NOSPC = ((ULONG)-28),
    /* This is an invalid seek */
    NL_ERROR_SPIPE = ((ULONG)-29),
    /* A read-only file system */
    NL_ERROR_ROFS = ((ULONG)-30),
    /* There are too many links */
    NL_ERROR_MLINK = ((ULONG)-31),
    /* A broken pipe */
    NL_ERROR_PIPE = ((ULONG)-32),
    /* The mathematics argument is out of the domain of the function. */
    NL_ERROR_DOM = ((ULONG)-33),
    /* The result is too large / cannot be represented */
    NL_ERROR_RANGE = ((ULONG)-34),
    /* A resource deadlock would occur */
    NL_ERROR_DEADLK = ((ULONG)-36),

    /* The file name is too long */
    NL_ERROR_NAMETOOLONG = ((ULONG)-38),
    /* There are no locks available */
    NL_ERROR_NOLCK = ((ULONG)-39),

    /* The function is not implemented / not supported */
    NL_ERROR_NOSYS = ((ULONG)-40),
    /* The directory is not empty */
    NL_ERROR_NOTEMPTY = ((ULONG)-41),
    /* The byte sequence is illegal */
    NL_ERROR_ILSEQ = ((ULONG)-42),

    NL_ERROR_STRUNCATE = ((ULONG)-80),

    /* The address is already in use */
    NL_ERROR_ADDRINUSE = ((ULONG)-100),
    /* The requested address cannot be assigned: is is not available */
    NL_ERROR_ADDRNOTAVAIL = ((ULONG)-101),
    /* the address family is not supported by the protocol */
    NL_ERROR_AFNOSUPPORT = ((ULONG)-102),
    /* The operation / connection is already in progress */
    NL_ERROR_ALREADY = ((ULONG)-103),
    /* The message is bad */
    NL_ERROR_BADMSG = ((ULONG)-104),
    /* The operation was canceled */
    NL_ERROR_CANCELED = ((ULONG)-105),
    /* The software has caused a connection abort */
    NL_ERROR_CONNABORTED = ((ULONG)-106),
    /*The connection was refused */
    NL_ERROR_CONNREFUSED = ((ULONG)-107),
    /* The connection was reset by the peer */
    NL_ERROR_CONNRESET = ((ULONG)-108),
    /* The destination address is required */
    NL_ERROR_DESTADDRREQ = ((ULONG)-109),
    /*The host is unreachable */
    NL_ERROR_HOSTUNREACH = ((ULONG)-110),
    /* The identifier was removed */
    NL_ERROR_IDRM = ((ULONG)-111),
    /* The operations is in progress */
    NL_ERROR_INPROGRESS = ((ULONG)-112),
    /* The socket is already connected */
    NL_ERROR_ISCONN = ((ULONG)-113),
    /* There are too many levels of symbolic links. */
    NL_ERROR_LOOP = ((ULONG)-114),
    /*The message is too large */
    NL_ERROR_MSGSIZE = ((ULONG)-115),
    /* The network is down */
    NL_ERROR_NETDOWN = ((ULONG)-116),
    /* The network has dropped connection because of a reset (i.e. the
     * connection was aborted by the network)
    */
    NL_ERROR_NETRESET = ((ULONG)-117),
    /* The network is unreachable */
    NL_ERROR_NETUNREACH = ((ULONG)-118),
    /* There is no buffer space available */
    NL_ERROR_NOBUFS = ((ULONG)-119),
    /* There is no data available (on the stream head read queue) */
    NL_ERROR_NODATA = ((ULONG)-120),
    /* The link has been severed (it's reserved in posix) */
    NL_ERROR_NOLINK = ((ULONG)-121),
    /* There is no message of the desired type */
    NL_ERROR_NOMSG = ((ULONG)-122),
    /* The protocol is not available */
    NL_ERROR_NOPROTOOPT = ((ULONG)-123),
    /* We're out of streams resources */
    NL_ERROR_NOSR = ((ULONG)-124),
    /* This is not a stream */
    NL_ERROR_NOSTR = ((ULONG)-125),
    /* The socket is not connected */
    NL_ERROR_NOTCONN = ((ULONG)-126),
    /* The state is not recoverable */
    NL_ERROR_NOTRECOVERABLE = ((ULONG)-127),
    /* This is not a socket */
    NL_ERROR_NOTSOCK = ((ULONG)-128),
    /* The operation is not supported */
    NL_ERROR_NOTSUPP = ((ULONG)-129),
    /* The operation is not supported on socket */
    NL_ERROR_OPNOTSUPP = ((ULONG)-130),

    NL_ERROR_OTHER = ((ULONG)-131),
    /* The value is too large for the data type */
    NL_ERROR_OVERFLOW = ((ULONG)-132),
    /* The previous owner died */
    NL_ERROR_OWNERDEAD = ((ULONG)-133),
    /* A protocol error */
    NL_ERROR_PROTO = ((ULONG)-134),
    /* The protocol is not supported */
    NL_ERROR_PROTONOSUPPORT = ((ULONG)-135),
    /* This is a wrong protocol type for the socket */
    NL_ERROR_PROTOTYPE = ((ULONG)-136),
    /* The timer has expired (or, the stream ioctl has timed out) */
    NL_ERROR_TIME = ((ULONG)-137),
    /* The connection has timed out */
    NL_ERROR_TIMEDOUT = ((ULONG)-138),
    /* The given text file is busy */
    NL_ERROR_TXTBSY = ((ULONG)-139),
    /* The operation would block */
    NL_ERROR_WOULDBLOCK = ((ULONG)-140),
    /* The operation is not finished */
    NL_ERROR_PENDING = ((ULONG)-141),
} NL_ERROR;

static __inline
NlMapStatusToNlErr(NTSTATUS status)
{
    NL_ERROR ret;

    switch (status)
    {
    case STATUS_NOT_SUPPORTED:
      ret = NL_ERROR_NOTSUPP;
      break;
    case STATUS_INSUFFICIENT_RESOURCES:
      ret = NL_ERROR_NOMEM;
      break;
    case STATUS_SUCCESS:
      ret = NL_ERROR_SUCCESS;
      break;
    case STATUS_PENDING:
      ret = NL_ERROR_PENDING;
      break;
    case STATUS_CANCELLED:
      ret = NL_ERROR_CANCELED;
      break;
    case STATUS_INVALID_PARAMETER:
      ret = NL_ERROR_INVAL;
      break;
    case STATUS_OBJECT_NAME_EXISTS:
      ret = NL_ERROR_EXIST;
      break;
    case STATUS_INVALID_MESSAGE:
      ret = NL_ERROR_BADMSG;
      break;
    default:
      ret = NL_ERROR_OTHER;
      break;
    }

    return ret;
}
