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

#include <config.h>

#include "cpu.h"
#include "openvswitch/compiler.h"

#ifdef __x86_64__
#include <cpuid.h>
#include <inttypes.h>

#include "openvswitch/util.h"

enum x86_reg {
    EAX,
    EBX,
    ECX,
    EDX,
};
#define X86_LEAF_MASK 0x80000000
#define X86_EXT_FEATURES_LEAF 0x00000007
static bool x86_has_isa(uint32_t leaf, enum x86_reg reg, uint32_t bit)
{
    uint32_t regs[4];

    if (__get_cpuid_max(leaf & X86_LEAF_MASK, NULL) < leaf) {
        return false;
    }

    __cpuid_count(leaf, 0, regs[EAX], regs[EBX], regs[ECX], regs[EDX]);
    return (regs[reg] & ((uint32_t) 1 << bit)) != 0;
}

static bool x86_isa[OVS_CPU_ISA_X86_LAST - OVS_CPU_ISA_X86_FIRST + 1];
#define X86_ISA(leaf, reg, bit, name) \
OVS_CONSTRUCTOR(cpu_isa_ ## name) { \
    x86_isa[name - OVS_CPU_ISA_X86_FIRST] = x86_has_isa(leaf, reg, bit); \
}
X86_ISA(X86_EXT_FEATURES_LEAF, EBX,  8, OVS_CPU_ISA_X86_BMI2)
X86_ISA(X86_EXT_FEATURES_LEAF, EBX, 16, OVS_CPU_ISA_X86_AVX512F)
X86_ISA(X86_EXT_FEATURES_LEAF, EBX, 30, OVS_CPU_ISA_X86_AVX512BW)
X86_ISA(X86_EXT_FEATURES_LEAF, ECX,  1, OVS_CPU_ISA_X86_AVX512VBMI)
X86_ISA(X86_EXT_FEATURES_LEAF, ECX, 14, OVS_CPU_ISA_X86_VPOPCNTDQ)
#endif

bool
cpu_has_isa(enum ovs_cpu_isa isa OVS_UNUSED)
{
#ifdef __x86_64__
    if (isa >= OVS_CPU_ISA_X86_FIRST &&
        isa <= OVS_CPU_ISA_X86_LAST) {
        return x86_isa[isa - OVS_CPU_ISA_X86_FIRST];
    }
#endif
    return false;
}
