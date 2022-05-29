/*
 * Copyright (c) 2021 Red Hat, Inc.
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

#ifndef OPENVSWITCH_USDT_PROBES_H
#define OPENVSWITCH_USDT_PROBES_H 1

#ifdef HAVE_USDT_PROBES
#include <sys/sdt.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef HAVE_USDT_PROBES

#define GET_DTRACE_FUNC(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10,  \
                        NAME, ...) NAME

#define OVS_USDT_PROBE(provider, name, ...)                           \
    GET_DTRACE_FUNC(_0, ##__VA_ARGS__, DTRACE_PROBE10, DTRACE_PROBE9, \
                    DTRACE_PROBE8, DTRACE_PROBE7, DTRACE_PROBE6,      \
                    DTRACE_PROBE5, DTRACE_PROBE4, DTRACE_PROBE3,      \
                    DTRACE_PROBE2, DTRACE_PROBE1, DTRACE_PROBE)       \
        (provider, name, ##__VA_ARGS__)

#else

#define OVS_USDT_PROBE(...)

#endif

#ifdef  __cplusplus
}
#endif

#endif /* usdt-probes.h */
