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

#ifndef WMI_H
#define WMI_H 1

#include <windefs.h>
#include <Wbemidl.h>

static inline void fill_context(IWbemContext *pContext)
{
    VARIANT var;

    /* IncludeQualifiers. */
    VariantInit(&var);
    var.vt = VT_BOOL;
    var.boolVal = VARIANT_TRUE;
    pContext->lpVtbl->SetValue(pContext, L"IncludeQualifiers", 0, &var);
    VariantClear(&var);

    VariantInit(&var);
    var.vt = VT_I4;
    var.lVal = 0;
    pContext->lpVtbl->SetValue(pContext, L"PathLevel", 0, &var);
    VariantClear(&var);

    /* ExcludeSystemProperties. */
    VariantInit(&var);
    var.vt = VT_BOOL;
    var.boolVal = VARIANT_FALSE;
    pContext->lpVtbl->SetValue(pContext, L"ExcludeSystemProperties", 0, &var);
    VariantClear(&var);
}

boolean create_wmi_port(char *name);
boolean delete_wmi_port(char *name);

#endif /* wmi.h */
