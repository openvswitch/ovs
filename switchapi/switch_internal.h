/*
* Copyright (c) 2021 Intel Corporation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _switch_internal_h_
#define _switch_internal_h_

#include <stdio.h>
#include <switchapi/switch_status.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

char *switch_error_to_string(switch_status_t status);


#ifdef __cplusplus
}
#endif

#endif /* _switch_internal_h_ */
