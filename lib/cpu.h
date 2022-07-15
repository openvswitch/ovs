/*
 * Copyright (c) 2021, Red Hat, Inc.
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

#ifndef CPU_H
#define CPU_H 1

#include <stdbool.h>

enum ovs_cpu_isa {
    OVS_CPU_ISA_X86_FIRST,
    OVS_CPU_ISA_X86_BMI2 = OVS_CPU_ISA_X86_FIRST,
    OVS_CPU_ISA_X86_AVX512F,
    OVS_CPU_ISA_X86_AVX512BW,
    OVS_CPU_ISA_X86_AVX512VBMI,
    OVS_CPU_ISA_X86_AVX512VL,
    OVS_CPU_ISA_X86_VPOPCNTDQ,
    OVS_CPU_ISA_X86_LAST = OVS_CPU_ISA_X86_VPOPCNTDQ,
};

bool cpu_has_isa(enum ovs_cpu_isa);

#endif /* CPU_H */
