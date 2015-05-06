/* Copyright (c) 2015 Nicira, Inc.
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


#ifndef OVN_PIPELINE_H
#define OVN_PIPELINE_H 1

struct controller_ctx;

/* Logical ports. */
#define MFF_LOG_INPORT  MFF_REG6 /* Logical input port. */
#define MFF_LOG_OUTPORT MFF_REG7 /* Logical output port. */

void pipeline_init(void);
void pipeline_run(struct controller_ctx *);
void pipeline_destroy(struct controller_ctx *);

#endif /* ovn/pipeline.h */
