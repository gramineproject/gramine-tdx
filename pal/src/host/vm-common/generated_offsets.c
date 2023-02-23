#include "generated_offsets_build.h"
#include "pal.h"
#include "pal_common.h"

#include "kernel_sched.h"
#include "kernel_xsave.h"

const char* generated_offsets_name = "PAL_VM";

const struct generated_offset generated_offsets[] = {
    DEFINE(VM_XSAVE_ALIGN, VM_XSAVE_ALIGN),
    DEFINE(MSR_IA32_GS_BASE, MSR_IA32_GS_BASE),

    /* struct pal_tcb_vm */
    OFFSET(PAL_TCB_LIBOS_SYSCALLDB, pal_tcb_vm, common.libos_tcb),
    OFFSET(PAL_TCB_VM_USER_RIP, pal_tcb_vm, kernel_thread.context.user_rip),

    OFFSET(PAL_TCB_VM_CONTEXT_R8, pal_tcb_vm, kernel_thread.context.r8),
    OFFSET(PAL_TCB_VM_CONTEXT_R9, pal_tcb_vm, kernel_thread.context.r9),
    OFFSET(PAL_TCB_VM_CONTEXT_R10, pal_tcb_vm, kernel_thread.context.r10),
    OFFSET(PAL_TCB_VM_CONTEXT_R11, pal_tcb_vm, kernel_thread.context.r11),
    OFFSET(PAL_TCB_VM_CONTEXT_R12, pal_tcb_vm, kernel_thread.context.r12),
    OFFSET(PAL_TCB_VM_CONTEXT_R13, pal_tcb_vm, kernel_thread.context.r13),
    OFFSET(PAL_TCB_VM_CONTEXT_R14, pal_tcb_vm, kernel_thread.context.r14),
    OFFSET(PAL_TCB_VM_CONTEXT_R15, pal_tcb_vm, kernel_thread.context.r15),
    OFFSET(PAL_TCB_VM_CONTEXT_RDI, pal_tcb_vm, kernel_thread.context.rdi),
    OFFSET(PAL_TCB_VM_CONTEXT_RSI, pal_tcb_vm, kernel_thread.context.rsi),
    OFFSET(PAL_TCB_VM_CONTEXT_RBP, pal_tcb_vm, kernel_thread.context.rbp),
    OFFSET(PAL_TCB_VM_CONTEXT_RBX, pal_tcb_vm, kernel_thread.context.rbx),
    OFFSET(PAL_TCB_VM_CONTEXT_RDX, pal_tcb_vm, kernel_thread.context.rdx),
    OFFSET(PAL_TCB_VM_CONTEXT_RAX, pal_tcb_vm, kernel_thread.context.rax),
    OFFSET(PAL_TCB_VM_CONTEXT_RCX, pal_tcb_vm, kernel_thread.context.rcx),
    OFFSET(PAL_TCB_VM_CONTEXT_RSP, pal_tcb_vm, kernel_thread.context.rsp),
    OFFSET(PAL_TCB_VM_CONTEXT_RIP, pal_tcb_vm, kernel_thread.context.rip),
    OFFSET(PAL_TCB_VM_CONTEXT_RFLAGS, pal_tcb_vm, kernel_thread.context.rflags),
    OFFSET(PAL_TCB_VM_CONTEXT_FPREGS, pal_tcb_vm, kernel_thread.context.fpregs),
    /* below 5 fields are not used, but added here for completeness */
    OFFSET(PAL_TCB_VM_CONTEXT_CSGSFSSS, pal_tcb_vm, kernel_thread.context.csgsfsss),
    OFFSET(PAL_TCB_VM_CONTEXT_ERR, pal_tcb_vm, kernel_thread.context.err),
    OFFSET(PAL_TCB_VM_CONTEXT_TRAPNO, pal_tcb_vm, kernel_thread.context.trapno),
    OFFSET(PAL_TCB_VM_CONTEXT_OLDMASK, pal_tcb_vm, kernel_thread.context.oldmask),
    OFFSET(PAL_TCB_VM_CONTEXT_CR2, pal_tcb_vm, kernel_thread.context.cr2),

    OFFSET_T(XSAVE_HEADER_OFFSET, PAL_XREGS_STATE, header),

    OFFSET_END,
};
