/* Copyright (c) 2009 Nicira Networks
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

#ifndef VSWITCHD_MGMT_H
#define VSWITCHD_MGMT_H 1

void mgmt_init(void);
void mgmt_reconfigure(void);
bool mgmt_run(void);
void mgmt_wait(void);
uint64_t mgmt_get_mgmt_id(void);

#endif /* mgmt.h */
