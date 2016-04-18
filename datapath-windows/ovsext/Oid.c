/*
 * Copyright (c) 2014 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "precomp.h"
#include "Switch.h"
#include "Vport.h"
#include "NetProto.h"
#include "User.h"
#include "Flow.h"
#include "Event.h"
#include "User.h"
#include "Oid.h"

/* Due to an imported header file */
#pragma warning( disable:4505 )

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DISPATCH
#include "Debug.h"

typedef struct _OVS_OID_CONTEXT {
    NDIS_EVENT oidComplete;
    NDIS_STATUS status;
} OVS_OID_CONTEXT, *POVS_OID_CONTEXT;


VOID
OvsExtOidRequestComplete(NDIS_HANDLE filterModuleContext,
                         PNDIS_OID_REQUEST oidRequest,
                         NDIS_STATUS status);
static VOID
OvsOidRequestCompleteMethod(POVS_SWITCH_CONTEXT switchObject,
                            PNDIS_OID_REQUEST oidRequest,
                            PNDIS_OID_REQUEST origOidRequest,
                            NDIS_STATUS status);
static VOID
OvsOidRequestCompleteSetInfo(POVS_SWITCH_CONTEXT switchObject,
                            PNDIS_OID_REQUEST oidRequest,
                            PNDIS_OID_REQUEST origOidRequest,
                            NDIS_STATUS status);
static VOID
OvsOidRequestCompleteQuery(POVS_SWITCH_CONTEXT switchObject,
                           PNDIS_OID_REQUEST oidRequest,
                           PNDIS_OID_REQUEST origOidRequest,
                           NDIS_STATUS status);

static NDIS_STATUS
OvsProcessSetOidPortProp(POVS_SWITCH_CONTEXT switchObject,
                         PNDIS_OID_REQUEST oidRequest);
static NDIS_STATUS
OvsProcessSetOidPort(POVS_SWITCH_CONTEXT switchObject,
                     PNDIS_OID_REQUEST oidRequest);
static NDIS_STATUS
OvsProcessSetOidNic(POVS_SWITCH_CONTEXT switchObject,
                    PNDIS_OID_REQUEST oidRequest);

__inline BOOLEAN
OvsCheckOidHeaderFunc(PNDIS_OBJECT_HEADER header,
                  LONG propRev,
                  LONG propSize)
{
    return header->Type != NDIS_OBJECT_TYPE_DEFAULT ||
           header->Revision < propRev ||
           header->Size < propSize;
}

#define OvsCheckOidHeader(_hdr, _rev) \
        OvsCheckOidHeaderFunc(_hdr, _rev, ##NDIS_SIZEOF_##_rev)

static __inline VOID
OvsOidSetOrigRequest(PNDIS_OID_REQUEST clonedRequest,
                     PNDIS_OID_REQUEST origRequest)
{
    *(PVOID*)(&clonedRequest->SourceReserved[0]) = origRequest;
}

static __inline PNDIS_OID_REQUEST
OvsOidGetOrigRequest(PNDIS_OID_REQUEST clonedRequest)
{
    return *((PVOID*)(&clonedRequest->SourceReserved[0]));
}

static __inline VOID
OvsOidSetContext(PNDIS_OID_REQUEST clonedRequest,
                 POVS_OID_CONTEXT origRequest)
{
    *(PVOID*)(&clonedRequest->SourceReserved[8]) = origRequest;
}

static __inline POVS_OID_CONTEXT
OvsOidGetContext(PNDIS_OID_REQUEST clonedRequest)
{
    return *((PVOID*)(&clonedRequest->SourceReserved[8]));
}

static NDIS_STATUS
OvsProcessSetOidPortProp(POVS_SWITCH_CONTEXT switchObject,
                         PNDIS_OID_REQUEST oidRequest)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    struct _SET *setInfo = &(oidRequest->DATA.SET_INFORMATION);
    PNDIS_SWITCH_PORT_PROPERTY_PARAMETERS portPropParam =
                                          setInfo->InformationBuffer;
    BOOLEAN checkFailed = TRUE;

    UNREFERENCED_PARAMETER(switchObject);

    if (setInfo->Oid == OID_SWITCH_PORT_PROPERTY_DELETE) {
        checkFailed = OvsCheckOidHeader(
                      (PNDIS_OBJECT_HEADER)portPropParam,
                      NDIS_SWITCH_PORT_PROPERTY_DELETE_PARAMETERS_REVISION_1);
    } else {
        /* it must be a add or update request */
        checkFailed = OvsCheckOidHeader(
                      (PNDIS_OBJECT_HEADER)portPropParam,
                      NDIS_SWITCH_PORT_PROPERTY_PARAMETERS_REVISION_1);
    }

    if (checkFailed) {
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto done;
    }

    if (portPropParam->PropertyType == NdisSwitchPortPropertyTypeVlan) {
        status = NDIS_STATUS_NOT_SUPPORTED;
        goto done;
    }

done:
    return status;
}

static NDIS_STATUS
OvsProcessSetOidPort(POVS_SWITCH_CONTEXT switchObject,
                     PNDIS_OID_REQUEST oidRequest)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    struct _SET *setInfo = &(oidRequest->DATA.SET_INFORMATION);
    PNDIS_SWITCH_PORT_PARAMETERS portParam = setInfo->InformationBuffer;

    if (OvsCheckOidHeader((PNDIS_OBJECT_HEADER)portParam,
                           NDIS_SWITCH_PORT_PARAMETERS_REVISION_1)) {
        status = NDIS_STATUS_NOT_SUPPORTED;
        goto done;
    }

    if (portParam->IsValidationPort) {
        /* Validation ports are used internally by the Hyper-V switch
         * to validate and verify settings. We must skip handling them,
         * and return STATUS_SUCCESS as the OID result
         */
        return NDIS_STATUS_SUCCESS;
    }

    switch(setInfo->Oid) {
    case OID_SWITCH_PORT_CREATE:
        status = HvCreatePort(switchObject, portParam, 0);
        break;
    case OID_SWITCH_PORT_UPDATED:
        status = HvUpdatePort(switchObject, portParam);
       break;
    case OID_SWITCH_PORT_TEARDOWN:
        HvTeardownPort(switchObject, portParam);
        break;
    case OID_SWITCH_PORT_DELETE:
        HvDeletePort(switchObject, portParam);
        break;
    default:
        break;
    }

done:
    return status;
}

static NDIS_STATUS
OvsProcessSetOidNic(POVS_SWITCH_CONTEXT switchObject,
                    PNDIS_OID_REQUEST oidRequest)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    struct _SET *setInfo = &(oidRequest->DATA.SET_INFORMATION);
    PNDIS_SWITCH_NIC_PARAMETERS nicParam = setInfo->InformationBuffer;

    if (OvsCheckOidHeader((PNDIS_OBJECT_HEADER)nicParam,
                           NDIS_SWITCH_NIC_PARAMETERS_REVISION_1)) {
        status = NDIS_STATUS_NOT_SUPPORTED;
        goto done;
    }

    switch(setInfo->Oid) {
    case OID_SWITCH_NIC_CREATE:
        status = HvCreateNic(switchObject, nicParam);
        break;
    case OID_SWITCH_NIC_CONNECT:
        HvConnectNic(switchObject, nicParam);
        break;
    case OID_SWITCH_NIC_UPDATED:
        HvUpdateNic(switchObject, nicParam);
        break;
    case OID_SWITCH_NIC_DISCONNECT:
        HvDisconnectNic(switchObject, nicParam);
        break;
    case OID_SWITCH_NIC_DELETE:
        HvDeleteNic(switchObject, nicParam);
        break;
    default:
        break;
    }

done:
    return status;

}

static NDIS_STATUS
OvsProcessSetOid(POVS_SWITCH_CONTEXT switchObject,
                 PNDIS_OID_REQUEST oidRequest,
                 PBOOLEAN complete)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    struct _SET *setInfo = &(oidRequest->DATA.SET_INFORMATION);

    *complete = FALSE;

    OVS_LOG_TRACE("Enter: oidRequest %p, Oid: %lu",
                  oidRequest, setInfo->Oid);

    /* Verify the basic Oid paramters first */
    if (setInfo->InformationBufferLength &&
       (setInfo->InformationBufferLength < sizeof(NDIS_OBJECT_HEADER))) {
        status = NDIS_STATUS_INVALID_OID;
        OVS_LOG_INFO("Invalid input %d", setInfo->InformationBufferLength);
        goto error;
    }

    /* Documentation does not specify what should be done
     * if informationBuffer is not present. Although it mentions the
     * structure type informationBUffer points to for each oid request,
     * but it does not explicitly mention that it is a MUST.
     * hence we are following this scenario same way as what sample code
     * mentions. */
    if (!(setInfo->InformationBufferLength)) {
        /* We cannot do anything about this oid request,
         * lets just pass it down. */
        OVS_LOG_INFO("Buffer Length Zero");
        goto done;
    }

    switch(setInfo->Oid) {
    case OID_SWITCH_PORT_PROPERTY_ADD:
    case OID_SWITCH_PORT_PROPERTY_UPDATE:
    case OID_SWITCH_PORT_PROPERTY_DELETE:
        status = OvsProcessSetOidPortProp(switchObject, oidRequest);
    break;

    case OID_SWITCH_PORT_CREATE:
    case OID_SWITCH_PORT_UPDATED:
    case OID_SWITCH_PORT_TEARDOWN:
    case OID_SWITCH_PORT_DELETE:
        status = OvsProcessSetOidPort(switchObject, oidRequest);
    break;

    case OID_SWITCH_NIC_CREATE:
    case OID_SWITCH_NIC_CONNECT:
    case OID_SWITCH_NIC_UPDATED:
    case OID_SWITCH_NIC_DISCONNECT:
    case OID_SWITCH_NIC_DELETE:
        status = OvsProcessSetOidNic(switchObject, oidRequest);
    break;

    default:
        /* Non handled OID request */
        break;
    }

    if (status != NDIS_STATUS_SUCCESS) {
        goto error;
    }

    goto done;

error:
    *complete = TRUE;
done:
    OVS_LOG_TRACE("Exit: status %8x.", status);
    return status;
}

static NDIS_STATUS
OvsProcessMethodOid(POVS_SWITCH_CONTEXT switchObject,
                    PNDIS_OID_REQUEST oidRequest,
                    PBOOLEAN complete,
                    PULONG bytesNeededParam)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    struct _METHOD *methodInfo = &(oidRequest->DATA.METHOD_INFORMATION);
    struct _SET *nicReqSetInfo = NULL;
    PNDIS_OBJECT_HEADER header = NULL;
    PNDIS_OID_REQUEST nicOidRequest = NULL;

    UNREFERENCED_PARAMETER(switchObject);

    OVS_LOG_TRACE("Enter: oidRequest %p, Oid: %lu",
                  oidRequest, methodInfo->Oid);

    *complete = FALSE;
    *bytesNeededParam = 0;
    header = methodInfo->InformationBuffer;

    switch(methodInfo->Oid) {
    /* We deal with only OID_SWITCH_NIC_REQUEST as of now */
    case  OID_SWITCH_NIC_REQUEST:
        if (OvsCheckOidHeader(header,
            NDIS_SWITCH_NIC_OID_REQUEST_REVISION_1)) {
            OVS_LOG_INFO("Check Header failed");
            status = NDIS_STATUS_NOT_SUPPORTED;
            *complete = TRUE;
            goto done;
        }

        nicOidRequest = (((PNDIS_SWITCH_NIC_OID_REQUEST)header)->OidRequest);
        nicReqSetInfo = &(nicOidRequest->DATA.SET_INFORMATION);

        /* Fail the SR-IOV VF case */
        if ((nicOidRequest->RequestType == NdisRequestSetInformation) &&
                   (nicReqSetInfo->Oid == OID_NIC_SWITCH_ALLOCATE_VF)) {
            OVS_LOG_INFO("We do not support Oid: "
                         "OID_NIC_SWITCH_ALLOCATE_VF");
            status = NDIS_STATUS_FAILURE;
            *complete = TRUE;
        }
        break;
    default:
        /* No op */
        break;
    }

done:
    OVS_LOG_TRACE("Exit: status %8x.", status);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterOidRequest function.
 * --------------------------------------------------------------------------
 */

NDIS_STATUS
OvsExtOidRequest(NDIS_HANDLE filterModuleContext,
                 PNDIS_OID_REQUEST oidRequest)
{
    POVS_SWITCH_CONTEXT switchObject = (POVS_SWITCH_CONTEXT)filterModuleContext;
    NDIS_STATUS status;
    PNDIS_OID_REQUEST clonedOidRequest = NULL;
    struct _METHOD *methodInfo = &(oidRequest->DATA.METHOD_INFORMATION);
    BOOLEAN completeOid = FALSE;
    ULONG bytesNeeded = 0;

    OVS_LOG_TRACE("Enter: oidRequest %p, reqType: %d",
                  oidRequest, oidRequest->RequestType);
    status = NdisAllocateCloneOidRequest(switchObject->NdisFilterHandle,
                                         oidRequest, OVS_MEMORY_TAG,
                                         &clonedOidRequest);
    if (status != NDIS_STATUS_SUCCESS) {
        goto done;
    }

    NdisInterlockedIncrement(&(switchObject->pendingOidCount));

    /* set the original oid request in cloned one. */
    OvsOidSetOrigRequest(clonedOidRequest, oidRequest);
    OvsOidSetContext(clonedOidRequest, NULL);

    switch(clonedOidRequest->RequestType) {
    case NdisRequestSetInformation:
        status = OvsProcessSetOid(switchObject, clonedOidRequest,
                                                   &completeOid);
        break;
    case NdisRequestMethod:
        status = OvsProcessMethodOid(switchObject, clonedOidRequest,
                                     &completeOid, &bytesNeeded);
        break;
    default:
        /* We do not handle other request types as of now.
         * We are just a passthrough for those. */
        break;
    }

    if (completeOid == TRUE) {
        /* dont leave any reference back to original request,
         * even if we are freeing it up. */
        OVS_LOG_INFO("Complete True oidRequest %p.", oidRequest);
        OvsOidSetOrigRequest(clonedOidRequest, NULL);
        NdisFreeCloneOidRequest(switchObject->NdisFilterHandle,
                                             clonedOidRequest);
        methodInfo->BytesNeeded = bytesNeeded;
        NdisInterlockedDecrement(&switchObject->pendingOidCount);
        goto done;
    }

    /* pass the request down */
    status = NdisFOidRequest(switchObject->NdisFilterHandle, clonedOidRequest);
    if (status != NDIS_STATUS_PENDING) {
        OvsExtOidRequestComplete(switchObject, clonedOidRequest, status);
        /* sample code says so */
        status = NDIS_STATUS_PENDING;
    }

done:
    OVS_LOG_TRACE("Exit: status %8x.", status);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterOidRequestComplete function.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtOidRequestComplete(NDIS_HANDLE filterModuleContext,
                         PNDIS_OID_REQUEST oidRequest,
                         NDIS_STATUS status)
{
    POVS_SWITCH_CONTEXT switchObject = (POVS_SWITCH_CONTEXT)filterModuleContext;
    PNDIS_OID_REQUEST origReq = OvsOidGetOrigRequest(oidRequest);
    POVS_OID_CONTEXT oidContext = OvsOidGetContext(oidRequest);

    /* Only one of the two should be set */
    ASSERT(origReq != NULL || oidContext != NULL);
    ASSERT(oidContext != NULL || origReq != NULL);

    OVS_LOG_TRACE("Enter: oidRequest %p, reqType: %d",
                  oidRequest, oidRequest->RequestType);

    if (origReq == NULL) {
        NdisInterlockedDecrement(&(switchObject->pendingOidCount));
        oidContext->status = status;
        NdisSetEvent(&oidContext->oidComplete);
        OVS_LOG_INFO("Internally generated request");
        goto done;
    }

    switch(oidRequest->RequestType) {
    case NdisRequestMethod:
        OvsOidRequestCompleteMethod(switchObject, oidRequest,
                                    origReq, status);
        break;

    case NdisRequestSetInformation:
        OvsOidRequestCompleteSetInfo(switchObject, oidRequest,
                                     origReq, status);
        break;

    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    default:
        OvsOidRequestCompleteQuery(switchObject, oidRequest,
                                   origReq, status);
        break;
    }

    OvsOidSetOrigRequest(oidRequest, NULL);

    NdisFreeCloneOidRequest(switchObject->NdisFilterHandle, oidRequest);
    NdisFOidRequestComplete(switchObject->NdisFilterHandle, origReq, status);
    NdisInterlockedDecrement(&(switchObject->pendingOidCount));

done:
    OVS_LOG_TRACE("Exit");
}

static VOID
OvsOidRequestCompleteMethod(POVS_SWITCH_CONTEXT switchObject,
                            PNDIS_OID_REQUEST oidRequest,
                            PNDIS_OID_REQUEST origOidRequest,
                            NDIS_STATUS status)
{
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(switchObject);

    struct _METHOD *methodInfo = &(oidRequest->DATA.METHOD_INFORMATION);
    struct _METHOD *origMethodInfo = &(origOidRequest->DATA.
                                       METHOD_INFORMATION);

    OVS_LOG_TRACE("Enter: oidRequest %p, Oid: %lu",
                  oidRequest, methodInfo->Oid);

    origMethodInfo->OutputBufferLength = methodInfo->OutputBufferLength;
    origMethodInfo->BytesRead = methodInfo->BytesRead;
    origMethodInfo->BytesNeeded = methodInfo->BytesNeeded;
    origMethodInfo->BytesWritten = methodInfo->BytesWritten;

    OVS_LOG_TRACE("Exit");
}

static VOID
OvsOidRequestCompleteSetInfo(POVS_SWITCH_CONTEXT switchObject,
                             PNDIS_OID_REQUEST oidRequest,
                             PNDIS_OID_REQUEST origOidRequest,
                             NDIS_STATUS status)
{
    struct _SET *setInfo = &(oidRequest->DATA.SET_INFORMATION);
    struct _SET *origSetInfo = &(origOidRequest->DATA.SET_INFORMATION);
    PNDIS_OBJECT_HEADER origHeader = origSetInfo->InformationBuffer;

    OVS_LOG_TRACE("Enter: oidRequest %p, Oid: %lu",
                  oidRequest, setInfo->Oid);

    origSetInfo->BytesRead = setInfo->BytesRead;
    origSetInfo->BytesNeeded = setInfo->BytesNeeded;

    if (status != NDIS_STATUS_SUCCESS) {

        switch(setInfo->Oid) {
        case OID_SWITCH_PORT_CREATE:
            HvDeletePort(switchObject,
                         (PNDIS_SWITCH_PORT_PARAMETERS)origHeader);
            break;

        case OID_SWITCH_NIC_CREATE:
            HvDeleteNic(switchObject,
                        (PNDIS_SWITCH_NIC_PARAMETERS)origHeader);
            break;

        default:
            break;
        }
    }

    OVS_LOG_TRACE("Exit");
}

static VOID
OvsOidRequestCompleteQuery(POVS_SWITCH_CONTEXT switchObject,
                           PNDIS_OID_REQUEST oidRequest,
                           PNDIS_OID_REQUEST origOidRequest,
                           NDIS_STATUS status)
{
    UNREFERENCED_PARAMETER(switchObject);
    UNREFERENCED_PARAMETER(status);

    struct _QUERY *queryInfo = &((oidRequest->DATA).QUERY_INFORMATION);
    struct _QUERY *origQueryInfo = &((origOidRequest->DATA).QUERY_INFORMATION);

    OVS_LOG_TRACE("Enter: oidRequest %p, Oid: %lu",
                  oidRequest, queryInfo->Oid);

    origQueryInfo->BytesWritten = queryInfo->BytesWritten;
    origQueryInfo->BytesNeeded = queryInfo->BytesNeeded;

    OVS_LOG_TRACE("Exit");
}

/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterCancelOidRequest function.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtCancelOidRequest(NDIS_HANDLE filterModuleContext,
                       PVOID requestId)
{
    OVS_LOG_TRACE("Enter: requestId: %p", requestId);

    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(requestId);
}


/*
 * --------------------------------------------------------------------------
 * Utility function to issue the specified OID to the NDIS stack. The OID is
 * directed towards the miniport edge of the extensible switch.
 * An OID that gets issued may not complete immediately, and in such cases, the
 * function waits for the OID to complete. Thus, this function must not be
 * called at the PASSIVE_LEVEL.
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
OvsIssueOidRequest(POVS_SWITCH_CONTEXT switchContext,
                   NDIS_REQUEST_TYPE oidType,
                   UINT32 oidRequestEnum,
                   PVOID oidInputBuffer,
                   UINT32 inputSize,
                   PVOID oidOutputBuffer,
                   UINT32 outputSize,
                   UINT32 *outputSizeNeeded)
{
    NDIS_STATUS status;
    PNDIS_OID_REQUEST oidRequest;
    POVS_OID_CONTEXT oidContext;
    ULONG OvsExtOidRequestId =          'ISVO';

    DBG_UNREFERENCED_PARAMETER(inputSize);
    DBG_UNREFERENCED_PARAMETER(oidInputBuffer);

    OVS_LOG_TRACE("Enter: switchContext: %p, oidType: %d",
                  switchContext, oidType);

    ASSERT(oidInputBuffer == NULL || inputSize != 0);
    ASSERT(oidOutputBuffer == NULL || outputSize != 0);
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    oidRequest = OvsAllocateMemoryWithTag(sizeof *oidRequest,
                                          OVS_OID_POOL_TAG);
    if (!oidRequest) {
        status = NDIS_STATUS_RESOURCES;
        goto done;
    }

    oidContext = OvsAllocateMemoryWithTag(sizeof *oidContext,
                                          OVS_OID_POOL_TAG);
    if (!oidContext) {
        OvsFreeMemoryWithTag(oidRequest, OVS_OID_POOL_TAG);
        status = NDIS_STATUS_RESOURCES;
        goto done;
    }

    RtlZeroMemory(oidRequest, sizeof *oidRequest);
    RtlZeroMemory(oidContext, sizeof *oidContext);

    oidRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    oidRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    oidRequest->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;

    oidRequest->RequestType = oidType;
    oidRequest->PortNumber = 0;
    oidRequest->Timeout = 0;
    oidRequest->RequestId = (PVOID)OvsExtOidRequestId;

    switch(oidType) {
    case NdisRequestQueryInformation:
        oidRequest->DATA.QUERY_INFORMATION.Oid = oidRequestEnum;
        oidRequest->DATA.QUERY_INFORMATION.InformationBuffer = oidOutputBuffer;
        oidRequest->DATA.QUERY_INFORMATION.InformationBufferLength = outputSize;
        break;
    default:
        ASSERT(FALSE);
        status = NDIS_STATUS_INVALID_PARAMETER;
        break;
    }

    /*
     * We make use of the SourceReserved field in the OID request to store
     * pointers to the original OID (if any), and also context for completion
     * (if any).
     */
    oidContext->status = NDIS_STATUS_SUCCESS;
    NdisInitializeEvent(&oidContext->oidComplete);

    OvsOidSetOrigRequest(oidRequest, NULL);
    OvsOidSetContext(oidRequest, oidContext);

    NdisInterlockedIncrement(&(switchContext->pendingOidCount));
    status = NdisFOidRequest(switchContext->NdisFilterHandle, oidRequest);
    if (status == NDIS_STATUS_PENDING) {
        NdisWaitEvent(&oidContext->oidComplete, 0);
    } else {
        NdisInterlockedDecrement(&(switchContext->pendingOidCount));
    }

    if (status == NDIS_STATUS_INVALID_LENGTH ||
        oidContext->status == NDIS_STATUS_INVALID_LENGTH) {
        switch(oidType) {
        case NdisRequestQueryInformation:
            *outputSizeNeeded = oidRequest->DATA.QUERY_INFORMATION.BytesNeeded;
        }
    }

    status = oidContext->status;
    ASSERT(status != NDIS_STATUS_PENDING);

    OvsFreeMemoryWithTag(oidRequest, OVS_OID_POOL_TAG);
    OvsFreeMemoryWithTag(oidContext, OVS_OID_POOL_TAG);

done:
    OVS_LOG_TRACE("Exit: status %8x.", status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Utility function to query if the extensible switch has completed activation
 * successfully.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsQuerySwitchActivationComplete(POVS_SWITCH_CONTEXT switchContext,
                                 BOOLEAN *switchActive)
{
    NDIS_STATUS status;
    PNDIS_SWITCH_PARAMETERS switchParams;
    UINT32 outputSizeNeeded;

    OVS_LOG_TRACE("Enter: switchContext: %p, switchActive: %p",
                  switchContext, switchActive);

    switchParams = OvsAllocateMemoryWithTag(sizeof *switchParams,
                                            OVS_OID_POOL_TAG);
    if (!switchParams) {
        status = NDIS_STATUS_RESOURCES;
        goto done;
    }

    /*
     * Even though 'switchParms' is supposed to be populated by the OID, it
     * needs to be initialized nevertheless. Otherwise, OID returns
     * NDIS_STATUS_INVALID_PARAMETER. This is not clear in the documentation.
     */
    RtlZeroMemory(switchParams, sizeof *switchParams);
    switchParams->Header.Revision = NDIS_SWITCH_PARAMETERS_REVISION_1;
    switchParams->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    switchParams->Header.Size = NDIS_SIZEOF_NDIS_SWITCH_PARAMETERS_REVISION_1;

    status = OvsIssueOidRequest(switchContext, NdisRequestQueryInformation,
                                OID_SWITCH_PARAMETERS, NULL, 0,
                                (PVOID)switchParams, sizeof *switchParams,
                                &outputSizeNeeded);

    ASSERT(status != NDIS_STATUS_INVALID_LENGTH);
    ASSERT(status != NDIS_STATUS_PENDING);
    if (status == NDIS_STATUS_SUCCESS) {
        ASSERT(switchParams->Header.Type == NDIS_OBJECT_TYPE_DEFAULT);
        ASSERT(switchParams->Header.Revision == NDIS_SWITCH_PARAMETERS_REVISION_1);
        ASSERT(switchParams->Header.Size ==
                NDIS_SIZEOF_NDIS_SWITCH_PARAMETERS_REVISION_1);
        *switchActive = switchParams->IsActive;
    }

    OvsFreeMemoryWithTag(switchParams, OVS_OID_POOL_TAG);

done:
    OVS_LOG_TRACE("Exit: status %8x, switchActive: %d.",
                  status, *switchActive);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Utility function to get the array of ports on the extensible switch. Upon
 * success, the caller needs to free the returned array.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsGetPortsOnSwitch(POVS_SWITCH_CONTEXT switchContext,
                    PNDIS_SWITCH_PORT_ARRAY *portArrayOut)
{
    PNDIS_SWITCH_PORT_ARRAY portArray;
    UINT32 arraySize = sizeof *portArray;
    NDIS_STATUS status = NDIS_STATUS_FAILURE;

    OVS_LOG_TRACE("Enter: switchContext: %p, portArray: %p",
                  switchContext, portArrayOut);
    do {
        UINT32 reqdArraySize;

        portArray = OvsAllocateMemoryWithTag(arraySize, OVS_OID_POOL_TAG);
        if (!portArray) {
            status = NDIS_STATUS_RESOURCES;
            goto done;
        }

       /*
        * Even though 'portArray' is supposed to be populated by the OID, it
        * needs to be initialized nevertheless. Otherwise, OID returns
        * NDIS_STATUS_INVALID_PARAMETER. This is not clear in the documentation.
        */
        RtlZeroMemory(portArray, sizeof *portArray);
        portArray->Header.Revision = NDIS_SWITCH_PORT_ARRAY_REVISION_1;
        portArray->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        portArray->Header.Size = NDIS_SIZEOF_NDIS_SWITCH_PORT_ARRAY_REVISION_1;

        status = OvsIssueOidRequest(switchContext, NdisRequestQueryInformation,
                                    OID_SWITCH_PORT_ARRAY, NULL, 0,
                                    (PVOID)portArray, arraySize,
                                    &reqdArraySize);
        if (status == NDIS_STATUS_SUCCESS) {
            *portArrayOut = portArray;
            break;
        }

        OvsFreeMemoryWithTag(portArray, OVS_OID_POOL_TAG);
        arraySize = reqdArraySize;
        if (status != NDIS_STATUS_INVALID_LENGTH) {
            break;
        }
    } while(status == NDIS_STATUS_INVALID_LENGTH);

done:
    OVS_LOG_TRACE("Exit: status %8x.", status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Utility function to get the array of nics on the extensible switch. Upon
 * success, the caller needs to free the returned array.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsGetNicsOnSwitch(POVS_SWITCH_CONTEXT switchContext,
                   PNDIS_SWITCH_NIC_ARRAY *nicArrayOut)
{
    PNDIS_SWITCH_NIC_ARRAY nicArray;
    UINT32 arraySize = sizeof *nicArray;
    NDIS_STATUS status = NDIS_STATUS_FAILURE;

    OVS_LOG_TRACE("Enter: switchContext: %p, nicArray: %p",
                  switchContext, nicArrayOut);

    do {
        UINT32 reqdArraySize;

        nicArray = OvsAllocateMemoryWithTag(arraySize, OVS_OID_POOL_TAG);
        if (!nicArray) {
            status = NDIS_STATUS_RESOURCES;
            goto done;
        }

       /*
        * Even though 'nicArray' is supposed to be populated by the OID, it
        * needs to be initialized nevertheless. Otherwise, OID returns
        * NDIS_STATUS_INVALID_PARAMETER. This is not clear in the documentation.
        */
        RtlZeroMemory(nicArray, sizeof *nicArray);
        nicArray->Header.Revision = NDIS_SWITCH_NIC_ARRAY_REVISION_1;
        nicArray->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        nicArray->Header.Size = NDIS_SIZEOF_NDIS_SWITCH_NIC_ARRAY_REVISION_1;

        status = OvsIssueOidRequest(switchContext, NdisRequestQueryInformation,
                                    OID_SWITCH_NIC_ARRAY, NULL, 0,
                                    (PVOID)nicArray, arraySize,
                                    &reqdArraySize);
        if (status == NDIS_STATUS_SUCCESS) {
            *nicArrayOut = nicArray;
            break;
        }

        OvsFreeMemoryWithTag(nicArray, OVS_OID_POOL_TAG);
        arraySize = reqdArraySize;
        if (status != NDIS_STATUS_INVALID_LENGTH) {
            break;
        }
    } while(status == NDIS_STATUS_INVALID_LENGTH);

done:
    OVS_LOG_TRACE("Exit: status %8x.", status);
    return status;
}

VOID OvsFreeSwitchPortsArray(PNDIS_SWITCH_PORT_ARRAY portsArray)
{
    if (portsArray) {
        OvsFreeMemoryWithTag(portsArray, OVS_OID_POOL_TAG);
    }
}

VOID OvsFreeSwitchNicsArray(PNDIS_SWITCH_NIC_ARRAY nicsArray)
{
    if (nicsArray) {
        OvsFreeMemoryWithTag(nicsArray, OVS_OID_POOL_TAG);
    }
}
