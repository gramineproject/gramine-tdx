/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for FP regs aka xsave (via `xsave`/`xrstor` instructions). Note that we only support
 * x86-64 CPUs that have the XSAVE feature. */

#pragma once

#include <stdint.h>

#define VM_XSAVE_ALIGN 64
#define VM_XSAVE_RESET_STATE_SIZE (512 + 64) /* 512 for legacy regs, 64 for xsave header */

enum VM_XFEATURE {
    VM_XFEATURE_FP,
    VM_XFEATURE_SSE,
    VM_XFEATURE_YMM,
    VM_XFEATURE_BNDREGS,
    VM_XFEATURE_BNDCSR,
    VM_XFEATURE_OPMASK,
    VM_XFEATURE_ZMM_Hi256,
    VM_XFEATURE_Hi16_ZMM,
    VM_XFEATURE_PT,
    VM_XFEATURE_PKRU,
};

#define VM_XFEATURE_MASK_FP        (1UL << VM_XFEATURE_FP)
#define VM_XFEATURE_MASK_SSE       (1UL << VM_XFEATURE_SSE)
#define VM_XFEATURE_MASK_YMM       (1UL << VM_XFEATURE_YMM)
#define VM_XFEATURE_MASK_BNDREGS   (1UL << VM_XFEATURE_BNDREGS)
#define VM_XFEATURE_MASK_BNDCSR    (1UL << VM_XFEATURE_BNDCSR)
#define VM_XFEATURE_MASK_OPMASK    (1UL << VM_XFEATURE_OPMASK)
#define VM_XFEATURE_MASK_ZMM_Hi256 (1UL << VM_XFEATURE_ZMM_Hi256)
#define VM_XFEATURE_MASK_Hi16_ZMM  (1UL << VM_XFEATURE_Hi16_ZMM)
#define VM_XFEATURE_MASK_PT        (1UL << VM_XFEATURE_PT)
#define VM_XFEATURE_MASK_PKRU      (1UL << VM_XFEATURE_PKRU)

#define VM_XFEATURE_MASK_FPSSE     (VM_XFEATURE_MASK_FP | VM_XFEATURE_MASK_SSE)
#define VM_XFEATURE_MASK_AVX512    (VM_XFEATURE_MASK_OPMASK | VM_XFEATURE_MASK_ZMM_Hi256 \
                                      | VM_XFEATURE_MASK_Hi16_ZMM)

extern uint32_t g_xsave_size;
extern const uint32_t g_xsave_reset_state[VM_XSAVE_RESET_STATE_SIZE / sizeof(uint32_t)];

int xsave_init(void);
