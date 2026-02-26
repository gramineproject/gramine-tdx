/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Enablement of XSAVE features.
 *
 * Notes on multi-core synchronization:
 *   - All functions are called at init, no sync required
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_xsave.h"

#define CPUID_FEATURE_XSAVE   (1UL << 26)
#define CPUID_FEATURE_OSXSAVE (1UL << 27)

uint64_t g_xcr0 = 0;
uint32_t g_xsave_size = 0;

const uint32_t g_xsave_reset_state[VM_XSAVE_RESET_STATE_SIZE / sizeof(uint32_t)]
        __attribute__((aligned(VM_XSAVE_ALIGN))) = {
    0x037F, 0, 0, 0, 0, 0, 0x1F80,     0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0,          0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,      0, 0, 0, 0, 0, 0x80000000, 0,      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    // XCOMP_BV[63] = 1, compaction mode
};

int xsave_init(void) {
    /* OSXSAVE bit in CR4 as well as SSE/x87 bits in XCR0 were already set in bootloader */
    uint64_t xcr0 = VM_XFEATURE_MASK_FPSSE;

    unsigned int words[4];
    cpuid(FEATURE_FLAGS_LEAF, 0, words);

    if (!(words[CPUID_WORD_ECX] & CPUID_FEATURE_XSAVE) ||
        !(words[CPUID_WORD_ECX] & CPUID_FEATURE_OSXSAVE))
        return -PAL_ERROR_INVAL;

    cpuid(EXTENDED_STATE_LEAF, 0, words);

    uint32_t xsavesize = words[CPUID_WORD_ECX];
    uint64_t xfeatures = words[CPUID_WORD_EAX] | ((uint64_t)words[CPUID_WORD_EDX] << 32);
    if (!xsavesize || !xfeatures)
        return -PAL_ERROR_INVAL;

    if (!(xfeatures & ~VM_XFEATURE_MASK_FPSSE)) {
        /* VM supports only x87 and SSE, can't use XSAVE (it was introduced with AVX) */
        return -PAL_ERROR_INVAL;
    }

    /* enable AVX256 in XCR0 if available in CPUID leaf (here and below, see Intel SDM, Vol. 1,
     * Chapter 13.3, notes on relation between CPUID and XCR0) */
    if (xfeatures & VM_XFEATURE_MASK_YMM)
        xcr0 |= VM_XFEATURE_MASK_YMM;

    /* we never enable MPX; note that it is also always forced to 0 in Intel TDX */

    /* enable AVX512; note that these 3 bits must be always set together or not set at all */
    if ((xfeatures & VM_XFEATURE_MASK_AVX512) == VM_XFEATURE_MASK_AVX512)
        xcr0 |= VM_XFEATURE_MASK_AVX512;

    /* we never enable PKRU -- it is not used by Gramine in any way */

    /* enable AMX's XTILECFG */
    if (xfeatures & VM_XFEATURE_MASK_AMX_CFG)
        xcr0 |= VM_XFEATURE_MASK_AMX_CFG;

    /* enable AMX's XTILEDATA */
    if (xfeatures & VM_XFEATURE_MASK_AMX_DATA)
        xcr0 |= VM_XFEATURE_MASK_AMX_DATA;

    __asm__ volatile("xsetbv" : : "a"(xcr0), "c"(0), "d"(0));

    g_xcr0 = xcr0;
    g_xsave_size = xsavesize;
    return 0;
}
