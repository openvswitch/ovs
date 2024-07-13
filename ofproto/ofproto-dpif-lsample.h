/*
 * Copyright (c) 2024 Red Hat, Inc.
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

#ifndef OFPROTO_DPIF_LSAMPLE_H
#define OFPROTO_DPIF_LSAMPLE_H 1

#include <stdbool.h>
#include <stdlib.h>

struct dpif_lsample;
struct ofproto_lsample_options;

struct dpif_lsample *dpif_lsample_create(void);

struct dpif_lsample *dpif_lsample_ref(const struct dpif_lsample *);
void dpif_lsample_unref(struct dpif_lsample *);

bool dpif_lsample_set_options(struct dpif_lsample *,
                              const struct ofproto_lsample_options *,
                              size_t n_opts);

#endif /* OFPROTO_DPIF_LSAMPLE_H */
