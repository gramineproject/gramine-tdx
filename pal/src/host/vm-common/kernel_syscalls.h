/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/* Declarations for syscalls. */

#pragma once

/* we only use MSRs relevant to 64-bit SYSCALL/SYSRET flows; thus we don't use legacy MSR_CSTAR */
/* these MSRs are allowed to be natively accessed in Intel TDX, so they don't need hardening */
#define MSR_STAR         0xc0000081 /* target CS/SS selectors from GDT */
#define MSR_LSTAR        0xc0000082 /* target 64-bit RIP on `syscall` instruction */
#define MSR_SYSCALL_MASK 0xc0000084 /* RFLAGS mask to apply on `syscall` instruction */

int syscalls_init(void);
