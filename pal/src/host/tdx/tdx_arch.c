/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tdx_arch.h"

/* input operands eax and ecx correspond to CPUID's leaf and subleaf */
long tdx_vmcall_instr_cpuid(uint64_t eax, uint64_t ecx, uint64_t* out_eax, uint64_t* out_ebx,
                            uint64_t* out_ecx, uint64_t* out_edx) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0xfc00, /* pass only R10-R15 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_INSTR_CPUID,
                                   .r12 = eax,
                                   .r13 = ecx };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;

    *out_eax = regs.r12;
    *out_ebx = regs.r13;
    *out_ecx = regs.r14;
    *out_edx = regs.r15;
    return 0;
}

/* interrupt_blocked should be false if interrupts are enabled in TD, true otherwise */
long tdx_vmcall_instr_hlt(bool interrupt_blocked) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x1c00, /* pass only R10-R12 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_INSTR_HLT,
                                   .r12 = (uint64_t)interrupt_blocked };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;
    return 0;
}

long tdx_vmcall_instr_io(uint64_t access_size, uint64_t direction, uint64_t ioport,
                         uint64_t* data) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0xfc00, /* pass only R10-R15 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_INSTR_IO,
                                   .r12 = access_size,
                                   .r13 = direction,
                                   .r14 = ioport,
                                   .r15 = (direction == TDG_VP_VMCALL_INSTR_IO_WRITE) ? *data : 0 };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;

    if (direction == TDG_VP_VMCALL_INSTR_IO_READ)
        *data = regs.r11;
    return 0;
}

long tdx_vmcall_instr_rdmsr(uint64_t msr_index, uint64_t* out_msr_value) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x1c00, /* pass only R10-R12 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_INSTR_RDMSR,
                                   .r12 = msr_index };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;

    *out_msr_value = regs.r11;
    return 0;
}

long tdx_vmcall_instr_wrmsr(uint64_t msr_index, uint64_t msr_value) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x3c00, /* pass only R10-R13 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_INSTR_WRMSR,
                                   .r12 = msr_index,
                                   .r13 = msr_value };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;
    return 0;
}

long tdx_vmcall_ve_reqmmio(uint64_t access_size, uint64_t direction, void* mmio_addr,
                           uint64_t* data) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0xfc00, /* pass only R10-R15 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_VE_REQMMIO,
                                   .r12 = access_size,
                                   .r13 = direction,
                                   .r14 = (uint64_t)mmio_addr,
                                   .r15 = (direction == TDG_VP_VMCALL_INSTR_IO_WRITE) ? *data : 0 };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;

    if (direction == TDG_VP_VMCALL_INSTR_IO_READ)
        *data = regs.r11;
    return 0;
}

/* CPUID-like function for querying TD functionality, currently reserved and unused */
long tdx_vmcall_gettdvmcallinfo(uint64_t leaf, uint64_t* out_r11, uint64_t* out_r12,
                                uint64_t* out_r13, uint64_t* out_r14) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x7c00, /* pass only R10-R14 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_GETTDVMCALLINFO,
                                   .r12 = leaf };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;

    *out_r11 = regs.r11;
    *out_r12 = regs.r12;
    *out_r13 = regs.r13;
    *out_r14 = regs.r14;
    return 0;
}

/* request host VMM to map a GPA range as private- or shared-memory mappings (depends on addr's
 * Shared bit); this func may also be used to convert page mappings from private to shared and vice
 * versa (shared -> private requires a followup TDG_MEM_PAGE_ACCEPT) */
long tdx_vmcall_mapgpa(uint64_t addr, uint64_t size, uint64_t* out_failed_addr) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x3c00, /* pass only R10-R13 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_MAPGPA,
                                   .r12 = addr,   /* addr and size must be 4KB aligned */
                                   .r13 = size };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS) {
        if (regs.r10 == TDG_VP_VMCALL_STATUS_RETRY || regs.r10 == TDG_VP_VMCALL_STATUS_GPA_INUSE)
            *out_failed_addr = regs.r11;
        return (long)regs.r10;
    }
    return 0;
}

/* request host VMM to generate a TD Quote based on the TD Report provided in a shared memory region
 * [addr, addr+size); this func returns immediately but the TD Quote is generated later -- host VMM
 * informs us about this event via an interrupt (we must check that shared memory region's Status
 * Code field changed from GET_QUOTE_IN_FLIGHT to GET_QUOTE_SUCCESS) */
long tdx_vmcall_getquote(uint64_t addr, uint64_t size) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x3c00, /* pass only R10-R13 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_GETQUOTE,
                                   .r12 = addr,   /* addr and size must be 4KB aligned */
                                   .r13 = size };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS) {
        return (long)regs.r10;
    }
    return 0;
}

/* error_code is in format: bits 31:0 -- TD-specific error code,
 *                          bits 62:32 -- TD-specific extended error code,
 *                          63 -- error_data_addr is valid and contains error-specific string;
 * error_data_addr is a 4KB shared memory region containing a zero-terminated string */
long tdx_vmcall_reportfatalerror(uint64_t error_code, uint64_t error_data_addr) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x3c00, /* pass only R10-R13 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_REPORTFATALERROR,
                                   .r12 = error_code,
                                   .r13 = error_data_addr };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS) {
        return (long)regs.r10;
    }
    return 0;
}

/* specify to host VMM which interrupt vector to use as an event-notify vector (e.g., to inform that
 * the TD Quote is ready); interrupt_vector can be 32..255 */
long tdx_vmcall_setupeventnotify(uint64_t interrupt_vector) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_VMCALL,
                                   .rcx = 0x1c00, /* pass only R10-R12 to host */
                                   .r10 = 0,      /* use r11 to choose sub-function */
                                   .r11 = TDG_VP_VMCALL_SETUPEVENTNOTIFY,
                                   .r12 = interrupt_vector };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    if (regs.r10 != TDG_VP_VMCALL_STATUS_SUCCESS)
        return (long)regs.r10;
    return 0;
}

/* accept a pending private page and initialize it to all-0; addr must be in special "EPT mapping"
 * format: bits 2:0 represent level, 11:3 are reserved, 51:12 represent GPA, 63:52 are reserved */
long tdx_tdcall_mem_page_accept(uint64_t addr) {
    struct tdx_tdcall_regs regs = {.rax = TDG_MEM_PAGE_ACCEPT,
                                   .rcx = addr };
    tdx_tdcall(&regs);

    /* SUCCESS, OPERAND_INVALID, OPERAND_BUSY, PAGE_ALREADY_ACCEPTED, PAGE_SIZE_MISMATCH */
    return (long)regs.rax;
}

/* create a TDREPORT_STRUCT object of this TD; additional user-defined data is taken from
 * tdreport_data_addr; the created object is put at tdreport_addr */
long tdx_tdcall_mr_report(uint64_t tdreport_addr, uint64_t tdreport_data_addr) {
    struct tdx_tdcall_regs regs = {.rax = TDG_MR_REPORT,
                                   .rcx = tdreport_addr,      /* out-arg; must be 1KB aligned */
                                   .rdx = tdreport_data_addr, /* in-arg;  must be 64B aligned */
                                   .r8  = 0 };                /* report sub-type, always 0 */
    tdx_tdcall(&regs);

    /* SUCCESS, OPERAND_INVALID, OPERAND_BUSY */
    return (long)regs.rax;
}

/* extend one of four RTMRs with 48B from the buffer at data_addr */
long tdx_tdcall_mr_rtmr_extend(uint64_t data_addr, uint64_t rtmr_index) {
    struct tdx_tdcall_regs regs = {.rax = TDG_MR_RTMR_EXTEND,
                                   .rcx = data_addr,     /* must be 64B aligned */
                                   .rdx = rtmr_index };  /* valid values: 0..3 */
    tdx_tdcall(&regs);

    /* SUCCESS, OPERAND_INVALID, OPERAND_BUSY */
    return (long)regs.rax;
}

/* read a TDX Module global-scope metadata field; can be invoked in a loop to get all fields --
 * start with `field_id == 0` and iterate over `*out_next_field_id` until the latter returns -1 */
long tdx_tdcall_sys_rd(uint64_t field_id, uint64_t* out_field_value, uint64_t* out_next_field_id) {
    struct tdx_tdcall_regs regs = {.rax = TDG_SYS_RD,
                                   .rdx = field_id };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* OPERAND_INVALID, OPERAND_BUSY */
        return (long)regs.rax;
    }

    *out_field_value = regs.r8;
    *out_next_field_id = regs.rdx;
    return 0;
}

/* read all guest-readable TDX Module global-scope metadata fields; can be invoked in a loop if all
 * fields do not fit in the 4KB-sized list at metadata_list_addr (similar to above function) */
long tdx_tdcall_sys_rdall(uint64_t metadata_list_addr, uint64_t field_id,
                          uint64_t* out_next_field_id) {
    struct tdx_tdcall_regs regs = {.rax = TDG_SYS_RDALL,
                                   .rdx = metadata_list_addr,  /* 4KB page */
                                   .r8  = field_id };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* OPERAND_INVALID, OPERAND_BUSY */
        return (long)regs.rax;
    }

    *out_next_field_id = regs.r8;
    return 0;
}

/* read a TD-scope metadata field (control structure field) */
long tdx_tdcall_vm_rd(uint64_t field_id, uint64_t* out_field_value, uint64_t* out_next_field_id) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VM_RD,
                                   .rdx = field_id };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* OPERAND_INVALID, OPERAND_BUSY */
        return (long)regs.rax;
    }

    *out_field_value = regs.r8;
    *out_next_field_id = regs.rdx;
    return 0;
}

/* write a TD-scope metadata field (control structure field) */
long tdx_tdcall_vm_wr(uint64_t field_id, uint64_t field_value, uint64_t field_value_mask,
                      uint64_t* out_old_field_value) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VM_WR,
                                   .rdx = field_id,
                                   .r8  = field_value,
                                   .r9  = field_value_mask };  /* which bits of R8 to write */
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* OPERAND_INVALID, OPERAND_BUSY */
        return (long)regs.rax;
    }

    *out_old_field_value = regs.r8;
    return 0;
}

/* read a VCPU-scope metadata field (control structure field) */
long tdx_tdcall_vp_rd(uint64_t field_id, uint64_t* out_field_value, uint64_t* out_next_field_id) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_RD,
                                   .rdx = field_id };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* OPERAND_INVALID, OPERAND_BUSY */
        return (long)regs.rax;
    }

    *out_field_value = regs.r8;
    *out_next_field_id = regs.rdx;
    return 0;
}

/* write a VCPU-scope metadata field (control structure field) */
long tdx_tdcall_vp_wr(uint64_t field_id, uint64_t field_value, uint64_t field_value_mask,
                      uint64_t* out_old_field_value) {
    struct tdx_tdcall_regs regs = {.rax = TDG_VP_WR,
                                   .rdx = field_id,
                                   .r8  = field_value,
                                   .r9  = field_value_mask };  /* which bits of R8 to write */
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* OPERAND_INVALID, OPERAND_BUSY */
        return (long)regs.rax;
    }

    *out_old_field_value = regs.r8;
    return 0;
}

/* get VCPU-specific TD execution environment information; see Table 6.321 for details */
long tdx_tdcall_vp_info(uint8_t* out_gpaw, uint64_t* out_attributes, uint32_t* out_num_vcpus,
                        uint32_t* out_max_vcpus, uint32_t* out_vcpu_index,
                        bool* out_sys_rd_available) {
    struct tdx_tdcall_regs regs = { .rax = TDG_VP_INFO };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* currently impossible because TDG_VP_INFO always returns success, but for sanity */
        return (long)regs.rax;
    }

    *out_gpaw       = (uint8_t)(regs.rcx & 0x3f);
    *out_attributes = regs.rdx;
    *out_num_vcpus  = (uint32_t)(regs.r8 & 0xffffffff);
    *out_max_vcpus  = (uint32_t)(regs.r8 >> 32);
    *out_vcpu_index = (uint32_t)(regs.r9 & 0xffffffff);
    *out_sys_rd_available = !!(regs.r10 & 0x1);
    return 0;
}

/* get VCPU-specific Virtualization Exception information for the recent #VE */
long tdx_tdcall_vp_veinfo_get(uint32_t* out_exit_reason, uint64_t* out_exit_qual,
                              uint64_t* out_guest_linear_addr, uint64_t* out_guest_physical_addr,
                              uint32_t* out_vmexit_instr_length, uint32_t* out_vmexit_instr_info) {
    struct tdx_tdcall_regs regs = { .rax = TDG_VP_VEINFO_GET };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS) {
        /* NO_VE_INFO */
        return (long)regs.rax;
    }

    *out_exit_reason         = (uint32_t)(regs.rcx & 0xffffffff);
    *out_exit_qual           = regs.rdx; /* exit qualification */
    *out_guest_linear_addr   = regs.r8;
    *out_guest_physical_addr = regs.r9;
    *out_vmexit_instr_length = (uint32_t)(regs.r10 & 0xffffffff);
    *out_vmexit_instr_info   = (uint32_t)(regs.r10 >> 32);
    return 0;
}

/* control unconditional #VE on CPUID instructions by the guest TD, see Table 6.4.11
 * (this TDCALL is deprecated in favor of TDCALL.VP.WR[CPUID_SUPERVISOR_VE / CPUID_USER_VE])
 *
 * format of RCX: bit 0     -- if set, CPUID executed in supervisor mode causes #VE unconditionally,
 *                bit 1     -- if set, CPUID executed in user mode causes #VE unconditionally,
 *                bits 63:2 -- reserved, must be 0
 */
long tdx_tdcall_vp_cpuidve_set(bool ve_in_supervisor_mode, bool ve_in_user_mode) {
    uint64_t rcx = 0;
    if (ve_in_supervisor_mode)
        rcx |= 1 << 0;
    if (ve_in_user_mode)
        rcx |= 1 << 1;

    struct tdx_tdcall_regs regs = {.rax = TDG_VP_CPUIDVE_SET,
                                   .rcx = rcx };
    tdx_tdcall(&regs);

    if (regs.rax != TDX_SUCCESS)
        return (long)regs.rax;
    return 0;
}
