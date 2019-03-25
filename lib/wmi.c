/*
 * Copyright (c) 2016 Cloudbase Solutions Srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "wmi.h"
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(wmi);

/* WMI Job values. */
enum job_status
{
    job_starting = 3,
    job_running = 4,
    job_completed = 7,
    job_wait = 4096
};

static char *
sanitize_port_name(char *name)
{
    char *p1, *p2;
    p1 = p2 = name;

    while (*p1) {
        if ((*p1) == '\'' || (*p1) == '\"') {
            p1++;
        } else {
            *p2 = *p1;
            p2++;
            p1++;
        }
    }
    *p2 = '\0';
    return name;
}

/* This function will output the appropriate message for a given HRESULT.*/
static void
get_hres_error(HRESULT hres)
{
    char *error_msg = NULL;

    if (FACILITY_WINDOWS == HRESULT_FACILITY(hres)) {
        hres = HRESULT_CODE(hres);
    }

    VLOG_ERR("%s", ovs_format_message(hres));
}

static boolean
check_return_value(HRESULT hres)
{
    if (FAILED(hres)) {
        get_hres_error(hres);
        return false;
    }

    return true;
}

static HRESULT
get_variant_value(IWbemClassObject *pcls_obj, wchar_t *field_name,
                  VARIANT *value)
{
    HRESULT hres;

    VariantInit(value);

    hres = pcls_obj->lpVtbl->Get(pcls_obj, field_name, 0, value, 0, 0);

    if (FAILED(hres)) {
        VariantClear(value);
    }

    return hres;
}

/* This function retrieves the uint16_t value from a given class object with
 * the field name field_name. */
static HRESULT
get_uint16_t_value(IWbemClassObject *pcls_obj, wchar_t *field_name,
                   uint16_t *value)
{
    VARIANT vt_prop;
    HRESULT hres = get_variant_value(pcls_obj, field_name, &vt_prop);
    *value = V_UI2(&vt_prop);

    return hres;
}

/* This function retrieves the unsigned int values from a given class object
 * with the field name field_name. */
static HRESULT
get_uint_value(IWbemClassObject *pcls_obj, wchar_t *field_name,
               unsigned int *value)
{
    VARIANT vt_prop;
    HRESULT hres = get_variant_value(pcls_obj, field_name, &vt_prop);
    *value = V_UI4(&vt_prop);

    return hres;
}

/* This function retrieves the unsigned short value from a given class object
 * with the field name field_name. */
static HRESULT
get_ushort_value(IWbemClassObject *pcls_obj, wchar_t *field_name,
                 unsigned short *value)
{
    VARIANT vt_prop;
    HRESULT hres = get_variant_value(pcls_obj, field_name, &vt_prop);
    *value = V_UI2(&vt_prop);

    return hres;
}

/* This function retrieves the BSTR value from a given class object with
 * the field name field_name, to a preallocated destination dest and with the
 * maximum length max_dest_lgth. */
static HRESULT
get_str_value(IWbemClassObject *pcls_obj, wchar_t *field_name, wchar_t *dest,
              int max_dest_lgth)
{
    VARIANT vt_prop;
    HRESULT hres = get_variant_value(pcls_obj, field_name, &vt_prop);

    if (wcscpy_s(dest, max_dest_lgth, vt_prop.bstrVal)) {
        VariantClear(&vt_prop);
        VLOG_WARN("get_str_value, wcscpy_s failed :%s", ovs_strerror(errno));
        return WBEM_E_FAILED;
    }

    VariantClear(&vt_prop);
    return S_OK;
}

/* This function waits for a WMI job to finish and retrieves the error code
 * if the job failed */
static HRESULT
wait_for_job(IWbemServices *psvc, wchar_t *job_path)
{
    IWbemClassObject *pcls_obj = NULL;
    HRESULT retval = 0;
    uint16_t job_state = 0;
    uint16_t error = 0;

    do {
        if(!check_return_value(psvc->lpVtbl->GetObject(psvc, job_path, 0, NULL,
                                                       &pcls_obj, NULL))) {
            retval = WBEM_E_FAILED;
            break;
        }

        retval = get_uint16_t_value(pcls_obj, L"JobState", &job_state);
        if (FAILED(retval)) {
            break;
        }

        if (job_state == job_starting || job_state == job_running) {
            Sleep(200);
        } else if (job_state == job_completed) {
            break;
        } else {
            /* Error occurred. */
            retval = get_uint16_t_value(pcls_obj, L"ErrorCode", &error);
            if (FAILED(retval)) {
                break;
            }
            VLOG_WARN("Job failed with error: %d", error);
            retval = WBEM_E_FAILED;;
            break;
        }

        if (pcls_obj != NULL) {
            pcls_obj->lpVtbl->Release(pcls_obj);
            pcls_obj = NULL;
        }
    } while(TRUE);

    if (pcls_obj != NULL) {
        pcls_obj->lpVtbl->Release(pcls_obj);
        pcls_obj = NULL;
    }

    return retval;
}

/* This function will initialize DCOM retrieving the WMI locator's ploc and
 * the context associated to it. */
static boolean
initialize_wmi(IWbemLocator **ploc, IWbemContext **pcontext)
{
    HRESULT hres = 0;

    /* Initialize COM. */
    hres = CoInitialize(NULL);

    if (FAILED(hres)) {
        return false;
    }

    /* Initialize COM security. */
    hres = CoInitializeSecurity(NULL,
                                -1,
                                NULL,
                                NULL,
                                RPC_C_AUTHN_LEVEL_DEFAULT,
                                RPC_C_IMP_LEVEL_IMPERSONATE,
                                NULL,
                                EOAC_NONE,
                                NULL);

    if (FAILED(hres)) {
        return false;
    }

    /* Fill context. */
    hres = CoCreateInstance(&CLSID_WbemContext,
                            NULL,
                            CLSCTX_INPROC_SERVER,
                            &IID_IWbemContext,
                            (void**)pcontext);

    if (FAILED(hres)) {
        return false;
    }

    fill_context(*pcontext);

    /* Initialize locator's (ploc) to WMI. */
    hres = CoCreateInstance(&CLSID_WbemLocator,
                            NULL,
                            CLSCTX_INPROC_SERVER,
                            &IID_IWbemLocator,
                            (LPVOID *)ploc);

    if (FAILED(hres)) {
        return false;
    }

    return true;
}

/* This function connects the WMI locator's ploc to a given WMI provider
 * defined in server and also sets the required security levels for a local
 * connection to it. */
static boolean
connect_set_security(IWbemLocator *ploc, IWbemContext *pcontext,
                     wchar_t *server, IWbemServices **psvc)
{
    HRESULT hres = 0;

   /* Connect to server. */
    hres = ploc->lpVtbl->ConnectServer(ploc,
                                       server,
                                       NULL,
                                       NULL,
                                       0,
                                       0,
                                       0,
                                       pcontext,
                                       psvc);

    if (FAILED(hres)) {
        return false;
    }

    /* Set security levels. */
    hres = CoSetProxyBlanket((IUnknown *) *psvc,
                             RPC_C_AUTHN_WINNT,
                             RPC_C_AUTHZ_NONE,
                             NULL,
                             RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE,
                             NULL,
                             EOAC_NONE);

    if (FAILED(hres)) {
        return false;
    }

    return true;
}

/* This function retrieves the first class object of a given enumeration
 * outputted by a query and fails if it could not retrieve the object or there
 * was no object to retrieve */
static boolean
get_first_element(IEnumWbemClassObject *penumerate,
                  IWbemClassObject **pcls_obj)
{
    unsigned long retval = 0;

    if (penumerate == NULL) {
        VLOG_WARN("Enumeration Class Object is NULL. Cannot get the first"
                  "object");
        return false;
    }

    HRESULT hres = penumerate->lpVtbl->Next(penumerate, WBEM_INFINITE, 1,
                                            pcls_obj, &retval);


    if (!check_return_value(hres) || retval == 0) {
        return false;
    }

    return true;
}

/* This function is a wrapper that transforms a char * into a wchar_t * */
static boolean
tranform_wide(char *name, wchar_t *wide_name)
{
    unsigned long size = strlen(name) + 1;
    long long ret = 0;

    if (wide_name == NULL) {
        VLOG_WARN("Provided wide string is NULL");
        return false;
    }

    ret = mbstowcs(wide_name, name, size);

    if (ret == -1) {
        VLOG_WARN("Invalid multibyte character is encountered");
        return false;
    } else if (ret == size) {
        VLOG_WARN("Returned wide string not NULL terminated");
        return false;
    }

    return true;
}

#define WMI_QUERY_COUNT 2048

/* This function will delete a switch internal port with a given name as input
 * executing "RemoveResourceSettings" as per documentation:
 * https://msdn.microsoft.com/en-us/library/hh850277%28v=vs.85%29.aspx
 * allocating the data and populating the needed fields to execute the
 * method */
boolean
delete_wmi_port(char *name)
{
    HRESULT hres = 0;
    boolean retval = true;

    IWbemLocator *ploc = NULL;
    IWbemServices *psvc = NULL;
    IWbemContext *pcontext = NULL;
    IWbemClassObject *pclass_instance = NULL;
    IWbemClassObject *pinput_params = NULL;
    IWbemClassObject *pcls_obj = NULL;
    IWbemClassObject *pout_params = NULL;
    IEnumWbemClassObject *penumerate = NULL;

    sanitize_port_name(name);
    VARIANT vt_prop;
    VARIANT variant_array;
    wchar_t *wide_name = NULL;
    VariantInit(&vt_prop);
    VariantInit(&variant_array);

    LONG count[1];
    SAFEARRAY* psa = SafeArrayCreateVector(VT_BSTR, 0, 1);
    if (psa == NULL) {
        VLOG_WARN("Could not allocate memory for a SAFEARRAY");
        retval = false;
        goto error;
    }

    if (!initialize_wmi(&ploc, &pcontext)) {
        VLOG_WARN("Could not initialize DCOM");
        retval = false;
        goto error;
    }

    if (!connect_set_security(ploc, pcontext, L"Root\\Virtualization\\v2",
                              &psvc)) {
        VLOG_WARN("Could not connect and set security for virtualization");
        retval = false;
        goto error;
    }


    /* Get the port with the element name equal to the name input. */
    wchar_t internal_port_query[WMI_QUERY_COUNT] = L"SELECT * from "
        L"Msvm_EthernetPortAllocationSettingData  WHERE ElementName = \"" ;

    wide_name = xmalloc((strlen(name) + 1) * sizeof(wchar_t));

    if (!tranform_wide(name, wide_name)) {
        retval = false;
        goto error;
    }
    wcscat_s(internal_port_query, WMI_QUERY_COUNT, wide_name);

    wcscat_s(internal_port_query, WMI_QUERY_COUNT, L"\"");

    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   internal_port_query,
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    /* Get the element path on the switch which will be deleted. */
    if (!get_first_element(penumerate, &pcls_obj)) {
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"__PATH", 0, &vt_prop, 0, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    /* Get the class object and the parameters it can have. */
    hres = psvc->lpVtbl->GetObject(psvc,
        L"Msvm_VirtualEthernetSwitchManagementService", 0, NULL, &pcls_obj,
        NULL);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = pcls_obj->lpVtbl->GetMethod(pcls_obj, L"RemoveResourceSettings", 0,
                                       &pinput_params, NULL);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    hres = pinput_params->lpVtbl->SpawnInstance(pinput_params, 0,
                                                &pclass_instance);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    count[0] = 0;

    hres = SafeArrayPutElement(psa, count, vt_prop.bstrVal);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    VariantClear(&vt_prop);
    VariantInit(&vt_prop);
    variant_array.vt = VT_ARRAY | VT_BSTR;
    variant_array.parray = psa;

    hres = pclass_instance->lpVtbl->Put(pclass_instance, L"ResourceSettings", 0,
                                        &variant_array, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    /* Get the object of the Msvm_VirtualEthernetSwitchManagementService which
     * we need to invoke the port deletion. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   L"SELECT * FROM "
                                   L"Msvm_VirtualEthernetSwitchManagementService",
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &pcls_obj)) {
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"__PATH", 0, &vt_prop, 0, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    /* Invoke the delete port method. */
    hres = psvc->lpVtbl->ExecMethod(psvc, vt_prop.bstrVal,
                                    L"RemoveResourceSettings", 0,
                                    pcontext, pclass_instance, &pout_params,
                                    NULL);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    VariantClear(&vt_prop);
    VariantInit(&vt_prop);

    hres = pout_params->lpVtbl->Get(pout_params, L"ReturnValue", 0,
                                    &vt_prop, NULL, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    unsigned int retvalue = 0;
    hres = get_uint_value(pout_params, L"ReturnValue", &retvalue);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (retvalue != 0 && retvalue != job_wait) {
        retval = false;
        goto error;
    }

    if (retvalue == job_wait) {
        WCHAR job_path[2048];
        hres = get_str_value(pout_params, L"Job", job_path,
                             sizeof(job_path) / sizeof(WCHAR));
        if (FAILED(hres)) {
            retval = false;
            goto error;
    }
        hres = wait_for_job(psvc, job_path);
        if (FAILED(hres)) {
            retval = false;
        }
    }

error:
    VariantClear(&vt_prop);

    if (pcontext != NULL) {
        pcontext->lpVtbl->Release(pcontext);
        pcontext = NULL;
    }
    if (psa != NULL) {
        SafeArrayDestroy(psa);
        psa = NULL;
    }
    if (pcls_obj != NULL) {
        pcls_obj->lpVtbl->Release(pcls_obj);
        pcls_obj = NULL;
    }
    if (wide_name != NULL) {
        free(wide_name);
        wide_name = NULL;
    }
    if (!retval) {
        get_hres_error(hres);
    }
    if (pinput_params != NULL) {
        pinput_params->lpVtbl->Release(pinput_params);
        pinput_params = NULL;
    }
    if (pout_params != NULL) {
        pout_params->lpVtbl->Release(pout_params);
        pout_params = NULL;
    }
    if (psvc != NULL) {
        psvc->lpVtbl->Release(psvc);
        psvc = NULL;
    }
    if (ploc != NULL) {
        ploc->lpVtbl->Release(ploc);
        ploc = NULL;
    }
    if (pclass_instance != NULL) {
        pclass_instance->lpVtbl->Release(pclass_instance);
        pclass_instance = NULL;
    }
    if (penumerate != NULL) {
        penumerate->lpVtbl->Release(penumerate);
        penumerate = NULL;
    }

    CoUninitialize();
    return retval;
}


/* This function will create an internal port on the switch given a given name
 * executing the method AddResourceSettings as per documentation:
 * https://msdn.microsoft.com/en-us/library/hh850019%28v=vs.85%29.aspx.
 * It will verify if the port is already defined, in which case it will use
 * the specific port, and if the forwarding extension "Open vSwitch Extension"
 * is enabled and running only on a single switch.
 * After the port is created and bound to the switch we will disable the
 * created net adapter and rename it to match the OVS bridge name .*/
boolean
create_wmi_port(char *name) {
    HRESULT hres = 0;
    boolean retval = true;

    BSTR text_object_string = NULL;

    IWbemLocator *ploc = NULL;
    IWbemContext *pcontext = NULL;
    IWbemServices *psvc = NULL;
    IEnumWbemClassObject *penumerate = NULL;
    IWbemClassObject *default_settings_data = NULL;
    IWbemClassObject *default_system = NULL;
    IWbemClassObject *pcls_obj = NULL;
    IWbemClassObject *pclass = NULL;
    IWbemClassObject *pinput_params = NULL;
    IWbemClassObject *pclass_instance = NULL;
    IWbemObjectTextSrc *text_object = NULL;
    IWbemClassObject *pout_params = NULL;

    wchar_t *wide_name = NULL;
    VARIANT vt_prop;
    VARIANT switch_setting_path;
    VARIANT new_name;
    SAFEARRAY *psa = SafeArrayCreateVector(VT_BSTR, 0, 1);
    VARIANT variant_array;
    LONG count[1];

    VariantInit(&vt_prop);
    VariantInit(&switch_setting_path);
    sanitize_port_name(name);

    if (psa == NULL) {
        VLOG_WARN("Could not allocate memory for a SAFEARRAY");
        retval = false;
        goto error;
    }

    if (!initialize_wmi(&ploc, &pcontext)) {
        VLOG_WARN("Could not initialize DCOM");
        retval = false;
        goto error;
    }

    if (!connect_set_security(ploc, pcontext, L"Root\\Virtualization\\v2",
                              &psvc)) {
        VLOG_WARN("Could not connect and set security for virtualization");
        retval = false;
        goto error;
    }

    /* Check if the element already exists on the switch. */
    wchar_t internal_port_query[WMI_QUERY_COUNT] = L"SELECT * FROM "
    L"CIM_EthernetPort WHERE ElementName = \"";

    wide_name = xmalloc((strlen(name) + 1) * sizeof(wchar_t));

    if (!tranform_wide(name, wide_name)) {
        retval = false;
        goto error;
    }

    wcscat_s(internal_port_query, WMI_QUERY_COUNT, wide_name);

    wcscat_s(internal_port_query, WMI_QUERY_COUNT, L"\"");
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   internal_port_query,
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("Port with name: %s already defined on the switch", name);
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    /* Check if the extension is enabled and running.  Also check if the
     * the extension is enabled on more than one switch. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   L"SELECT * "
                                   L"FROM Msvm_EthernetSwitchExtension "
                                   L"WHERE "
                                   L"ElementName=\"Open vSwitch Extension\" "
                                   L"AND EnabledState=2 "
                                   L"AND HealthState=5",
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("Open vSwitch Extension is not enabled on any switch");
        retval = false;
        goto error;
    }
    wcscpy_s(internal_port_query, WMI_QUERY_COUNT,
             L"SELECT * FROM Msvm_VirtualEthernetSwitch WHERE Name = \"");

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"SystemName", 0,
                                 &vt_prop, 0, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    wcscat_s(internal_port_query, WMI_QUERY_COUNT,
             vt_prop.bstrVal);

    VariantClear(&vt_prop);
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    if (get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("The extension is activated on more than one switch, "
                  "aborting operation. Please activate the extension on a "
                  "single switch");
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;
    if (pcls_obj != NULL) {
        pcls_obj->lpVtbl->Release(pcls_obj);
        pcls_obj = NULL;
    }

    /* Get the switch object on which the extension is activated. */
    wcscat_s(internal_port_query, WMI_QUERY_COUNT, L"\"");
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   internal_port_query,
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("Could not get the switch object on which the extension is"
                  "activated");
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"ElementName", 0, &vt_prop, 0, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    wcscpy_s(internal_port_query, WMI_QUERY_COUNT,
             L"SELECT * FROM Msvm_VirtualEthernetSwitchSettingData WHERE "
             L"ElementName = \"");

    wcscat_s(internal_port_query, WMI_QUERY_COUNT,
             vt_prop.bstrVal);
    VariantClear(&vt_prop);

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"Name", 0, &vt_prop, 0, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    /* Should be enough to give the InstanceID, from msdn documentation:
     * Uniquely identifies an instance of this class. This property is
     * inherited from CIM_SettingData and is always
     * set to "Microsoft:GUID\DeviceSpecificData". */
    wcscat_s(internal_port_query, WMI_QUERY_COUNT,
             L"\" AND InstanceID  = \"Microsoft:");
    wcscat_s(internal_port_query, WMI_QUERY_COUNT,
             vt_prop.bstrVal);
    wcscat_s(internal_port_query, WMI_QUERY_COUNT,
             L"\"");

    VariantClear(&vt_prop);

    /* Retrieve the Msvm_VirtualEthernetSwitchSettingData pinned to the switch
     * object on which the extension is activated. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   internal_port_query,
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("Could not get the first "
                  "Msvm_VirtualEthernetSwitchSettingData object");
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"__PATH", 0, &switch_setting_path,
                                 0, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    /* Retrieve a default allocation port.  This object will be later filled
     * with optional data to create an switch internal port. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   L"SELECT * FROM "
                                   L"Msvm_EthernetPortAllocationSettingData "
                                   L"WHERE InstanceID LIKE '%%%%\\\\Default' "
                                   L"AND ResourceSubType = "
                                   L"'Microsoft:Hyper-V:Ethernet Connection'",
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &default_settings_data)) {
        VLOG_WARN("Could not retrieve default allocation port object");
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    /* Retrieve the default computer system on which the port allocation will
     * be hosted.
     * Instead of querying using Description, we can query using InstallDate.
     * From MSDN documentation regarding InstallDate:
     * The date and time the virtual machine configuration was created for
     * a virtual machine, or Null, for a management operating system. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   L"SELECT * FROM Msvm_ComputerSystem WHERE "
                                   L"InstallDate is NULL",
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &default_system)) {
        VLOG_WARN("Could not retrieve default computer system object");
        retval = false;
        goto error;
    }

    hres = default_system->lpVtbl->Get(default_system, L"__PATH",
                                       0, &vt_prop, 0, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    count[0] = 0;
    hres = SafeArrayPutElement(psa, count, vt_prop.bstrVal);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    VariantClear(&vt_prop);
    variant_array.vt = VT_ARRAY | VT_BSTR;
    variant_array.parray = psa;
    hres = default_settings_data->lpVtbl->Put(default_settings_data,
                                              L"HostResource", 0,
                                              &variant_array, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = psvc->lpVtbl->GetObject(psvc,
                                   L"Msvm_VirtualEthernetSwitchManagementService",
                                   0, NULL, &pclass, NULL);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = pclass->lpVtbl->GetMethod(pclass, L"AddResourceSettings", 0,
                                     &pinput_params, NULL);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = pinput_params->lpVtbl->SpawnInstance(pinput_params, 0,
                                                &pclass_instance);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    /* Store the switch setting path retrieved above in the affected
     * configuration field of the class instance. */
    hres = pclass_instance->lpVtbl->Put(pclass_instance,
                                        L"AffectedConfiguration", 0,
                                        &switch_setting_path, 0);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    /* Store the port name in the ElementName field of the default allocation
     * data. */
    vt_prop.vt = VT_BSTR;
    vt_prop.bstrVal = SysAllocString(wide_name);
    hres = default_settings_data->lpVtbl->Put(default_settings_data,
                                              L"ElementName", 0,
                                              &vt_prop, 0);
    VariantClear(&vt_prop);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    /* Retrieve and store the serialized data of the modified default switch
     * settings data. */
    hres = CoCreateInstance(&CLSID_WbemObjectTextSrc,
                            NULL,
                            CLSCTX_INPROC_SERVER,
                            &IID_IWbemObjectTextSrc,
                            (void**)&text_object);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = text_object->lpVtbl->GetText(text_object, 0,
                                        default_settings_data,
                                        WMI_OBJ_TEXT_WMI_DTD_2_0,
                                        pcontext,
                                        &text_object_string);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    hres = SafeArrayDestroy(psa);
    if (FAILED(hres)) {
        VLOG_WARN("Could not clear the data of the array");
        retval = false;
        goto error;
    }

    psa = SafeArrayCreateVector(VT_BSTR, 0, 1);

    if (psa == NULL) {
        VLOG_WARN("Could not allocate memory for a SAFEARRAY");
        retval = false;
        goto error;
    }

    count[0] = 0;
    variant_array.parray = psa;
    hres = SafeArrayPutElement(psa, count, text_object_string);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    hres = pclass_instance->lpVtbl->Put(pclass_instance, L"ResourceSettings",
                                        0, &variant_array, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    /* Get the object of the switch service. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   L"SELECT * FROM "
                                   L"Msvm_VirtualEthernetSwitchManagementService",
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (!get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("Could not get the object of the switch service");
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;

    hres = pcls_obj->lpVtbl->Get(pcls_obj, L"__PATH", 0, &vt_prop, 0, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    /* Try to add the port to the switch. */
    hres = psvc->lpVtbl->ExecMethod(psvc, vt_prop.bstrVal,
                                    L"AddResourceSettings", 0,
                                    pcontext, pclass_instance, &pout_params,
                                    NULL);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    unsigned int retvalue = 0;
    hres = get_uint_value(pout_params, L"ReturnValue", &retvalue);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    if (retvalue != 0 && retvalue != job_wait) {
        retval = false;
        goto error;
    }

    if (retvalue == job_wait) {
        WCHAR job_path[2048];
        hres = get_str_value(pout_params, L"Job", job_path,
                             sizeof(job_path) / sizeof(WCHAR));
        if (FAILED(hres)) {
            retval = false;
            goto error;
        }
        hres = wait_for_job(psvc, job_path);
        if (FAILED(hres)) {
            retval = false;
            goto error;
        }
    }

    pclass->lpVtbl->Release(pclass);
    pclass = NULL;
    pclass_instance->lpVtbl->Release(pclass_instance);
    pclass_instance = NULL;
    pinput_params->lpVtbl->Release(pinput_params);
    pinput_params = NULL;
    psvc->lpVtbl->Release(psvc);
    psvc = NULL;
    VariantClear(&vt_prop);

    if (!connect_set_security(ploc, pcontext, L"Root\\StandardCimv2",
                              &psvc)) {
        VLOG_WARN("Could not connect and set security for CIM");
        retval = false;
        goto error;
    }

    wcscpy_s(internal_port_query, WMI_QUERY_COUNT,
             L"SELECT * FROM MSFT_NetAdapter WHERE Name LIKE '%%");
    wcscat_s(internal_port_query, WMI_QUERY_COUNT, wide_name);
    wcscat_s(internal_port_query, WMI_QUERY_COUNT, L"%%'");

    /* Get the object with the port name equal to name on the CIM. */
    hres = psvc->lpVtbl->ExecQuery(psvc,
                                   L"WQL",
                                   internal_port_query,
                                   WBEM_FLAG_FORWARD_ONLY |
                                   WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &penumerate);

    if (!get_first_element(penumerate, &pcls_obj)) {
        VLOG_WARN("Element name: %s not found in CIM", name);
        retval = false;
        goto error;
    }
    penumerate->lpVtbl->Release(penumerate);
    penumerate = NULL;
    pcls_obj->lpVtbl->Get(pcls_obj, L"__PATH", 0, &vt_prop, 0, 0);
    pcls_obj->lpVtbl->Release(pcls_obj);
    pcls_obj = NULL;

    /* Disable the adapter with port name equal with name. */
    hres = psvc->lpVtbl->ExecMethod(psvc, vt_prop.bstrVal, L"Disable", 0,
                                    pcontext, NULL, NULL, NULL);

    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = psvc->lpVtbl->GetObject(psvc, L"MSFT_NetAdapter", 0, NULL, &pclass,
                                   NULL);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = pclass->lpVtbl->GetMethod(pclass, L"Rename", 0, &pinput_params,
                                     NULL);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    hres = pinput_params->lpVtbl->SpawnInstance(pinput_params, 0,
                                                &pclass_instance);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }

    VariantInit(&new_name);
    new_name.vt = VT_BSTR;
    new_name.bstrVal = wide_name;
    hres = pclass_instance->lpVtbl->Put(pclass_instance, L"NewName", 0,
                                        &new_name, 0);
    if (FAILED(hres)) {
        retval = false;
        goto error;
    }
    hres = psvc->lpVtbl->ExecMethod(psvc, vt_prop.bstrVal, L"Rename", 0,
                                    pcontext, pclass_instance, NULL, NULL);
    if (FAILED(hres)) {
        retval = false;
    }

error:
    if (text_object_string != NULL) {
        SysFreeString(text_object_string);
        text_object_string = NULL;
    }
    if (psa != NULL) {
        SafeArrayDestroy(psa);
        psa = NULL;
    }
    if (ploc != NULL) {
        ploc->lpVtbl->Release(ploc);
        ploc = NULL;
    }
    if (pcontext != NULL) {
        pcontext->lpVtbl->Release(pcontext);
        pcontext = NULL;
    }
    if (psvc != NULL) {
        psvc->lpVtbl->Release(psvc);
        psvc = NULL;
    }
    if (penumerate != NULL) {
        penumerate->lpVtbl->Release(penumerate);
        penumerate = NULL;
    }
    if (default_settings_data != NULL) {
        default_settings_data->lpVtbl->Release(default_settings_data);
        default_settings_data = NULL;
    }
    if (default_system != NULL) {
        default_system->lpVtbl->Release(default_system);
        default_system = NULL;
    }
    if (pcls_obj != NULL) {
        pcls_obj->lpVtbl->Release(pcls_obj);
        pcls_obj = NULL;
    }
    if (pclass != NULL) {
        pclass->lpVtbl->Release(pclass);
        pclass = NULL;
    }
    if (pinput_params != NULL) {
        pinput_params->lpVtbl->Release(pinput_params);
        pinput_params = NULL;
    }
    if (pclass_instance != NULL) {
        pclass_instance->lpVtbl->Release(pclass_instance);
        pclass_instance = NULL;
    }
    if (text_object != NULL) {
        text_object->lpVtbl->Release(text_object);
        text_object = NULL;
    }
    if (pout_params != NULL) {
        pout_params->lpVtbl->Release(pout_params);
        pout_params = NULL;
    }
    if (wide_name != NULL) {
        free(wide_name);
        wide_name = NULL;
    }
    VariantClear(&vt_prop);
    VariantClear(&switch_setting_path);

    if (!retval) {
        get_hres_error(hres);
    }
    CoUninitialize();
    return retval;
}
