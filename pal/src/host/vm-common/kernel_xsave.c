/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_xsave.h"

#define CPUID_FEATURE_XSAVE   (1UL << 26)
#define CPUID_FEATURE_OSXSAVE (1UL << 27)

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
    unsigned int words[4];

    /* OSXSAVE bit in CR4 as well as AVX/SSE/x87 bits in XCR0 were already set in pal_start() */

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
        /* support only FP and SSE, can't use XSAVE (it was introduced with AVX) */
        return -PAL_ERROR_INVAL;
    }

    g_xsave_size = xsavesize;
    return 0;
}
