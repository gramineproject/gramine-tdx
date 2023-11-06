/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Declarations for scheduling and context switching. Also takes care of CPU affinity.
 */

#pragma once

#include <stdint.h>

#include "spinlock.h"

#include "kernel_interrupts.h"

#define MAX_NUM_CPUS 256
#define MAX_NUM_CPU_LONGS (MAX_NUM_CPUS / BITS_IN_TYPE(unsigned long))
static_assert(MAX_NUM_CPUS % BITS_IN_TYPE(unsigned long) == 0, "");

/*
 * FS_BASE: to allow apps (mainly Glibc) to set up Thread-Local Storage;
 * GS_BASE: used only in kernel mode, points to current TCB of Gramine thread;
 * GS_KERNEL_BASE: used only in kernel mode, points to per-CPU data
 */
#define MSR_IA32_FS_BASE        0xC0000100
#define MSR_IA32_GS_BASE        0xC0000101
#define MSR_IA32_GS_KERNEL_BASE 0xC0000102

extern bool g_kick_sched_thread;

/* the two helper functions are implemented in pal_common_threading.c which knows about the
 * relationship between the TCB (which is pointed to by GS base reg) and the thread struct */
struct thread* get_thread_ptr(uintptr_t curr_gs_base);
uintptr_t get_gs_base(struct thread* next_thread);

void sched_thread_uninterruptable(struct isr_regs* userland_regs);
void sched_thread(uint32_t* lock_to_unlock, int* clear_child_tid);
void sched_thread_wait(int* futex_word, spinlock_t* lock);
void sched_thread_wakeup_uninterruptable(int* futex_word);
void sched_thread_wakeup(int* futex_word);

void sched_thread_add(struct thread* thread);
void sched_thread_remove(struct thread* thread);
void sched_thread_set_cpu_affinity(struct thread* thread, unsigned long* cpu_mask,
                                   size_t cpu_mask_len);
