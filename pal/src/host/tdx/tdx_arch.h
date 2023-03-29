/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* TODO:
 *  - TD parameters: ATTRIBUTES, Table 4.6, page 32
 */

/* Table 6.278 "TDCALL Instruction Leaf Numbers Definition" from TDX Module ABI */
#define TDG_VP_VMCALL       0   /* call a host VM service */
#define TDG_VP_INFO         1   /* get TD execution environment information */
#define TDG_MR_RTMR_EXTEND  2   /* extend a TD runtime measurement register */
#define TDG_VP_VEINFO_GET   3   /* get Virtualization Exception info for the recent #VE */
#define TDG_MR_REPORT       4   /* create a cryptographic report of the TD */
#define TDG_VP_CPUIDVE_SET  5   /* control delivery of #VE on CPUID execution; see note below */
#define TDG_MEM_PAGE_ACCEPT 6   /* accept a pending private page into the TD */
#define TDG_VM_RD           7   /* read a TD-scope metadata field */
#define TDG_VM_WR           8   /* write a TD-scope metadata field */
#define TDG_VP_RD           9   /* read a VCPU-scope metadata field */
#define TDG_VP_WR           10  /* write a VCPU-scope metadata field */
#define TDG_SYS_RD          11  /* read a TDX Module global-scope metadata field */
#define TDG_SYS_RDALL       12  /* read all guest-readable TDX Module global-scope metadata */

/* NOTE on TDG_VP_CPUIDVE_SET: it is provided for backward compatibility and should not be used. The
 * TD may control the same settings by writing to the VCPU-scope metadata fields CPUID_SUPERVISOR_VE
 * and CPUID_USER_VE using TDG_VP_WR TDCALL. */

/* Tables 2-3 "TDG.VP.VMCALL codes" and 2-4 "TDG.VP.VMCALL Instruction execution sub-functions"
 * from TDX GHCI */
#define TDG_VP_VMCALL_INSTR_CPUID     0x0000a  /* Instruction.CPUID */
#define TDG_VP_VMCALL_INSTR_HLT       0x0000c  /* Instruction.HLT */
#define TDG_VP_VMCALL_INSTR_IO        0x0001e  /* Instruction.IO */
#define TDG_VP_VMCALL_INSTR_RDMSR     0x0001f  /* Instruction.RDMSR */
#define TDG_VP_VMCALL_INSTR_WRMSR     0x00020  /* Instruction.WRMSR */
#define TDG_VP_VMCALL_VE_REQMMIO      0x00030  /* #VE.RequestMMIO */
#define TDG_VP_VMCALL_INSTR_PCONFIG   0x00041  /* Instruction.PCONFIG -- unused for now */

#define TDG_VP_VMCALL_GETTDVMCALLINFO   0x10000  /* GetTdVmCallInfo (reserved) */
#define TDG_VP_VMCALL_MAPGPA            0x10001  /* map a GPA range as private or shared memory */
#define TDG_VP_VMCALL_GETQUOTE          0x10002  /* generate TD Quote for an input TD Report */
#define TDG_VP_VMCALL_REPORTFATALERROR  0x10003  /* inform host that TD experienced a fatal error */
#define TDG_VP_VMCALL_SETUPEVENTNOTIFY  0x10004  /* which interrupt vector to use as event notify */

/* Table 2-5 "TDCALL[TDG.VP.VMCALL] Completion Status Codes" (returned in high 32 bits of RAX) from
 * TDX GHCI and Tables 6.283 from TDX Module ABI */
#define TDX_SUCCESS                0x00000000
#define TDX_OPERAND_INVALID        0xc0000100
#define TDX_OPERAND_BUSY           0x80000200
#define TDX_PAGE_ALREADY_ACCEPTED  0x00000b0a
#define TDX_PAGE_SIZE_MISMATCH     0xc0000b0b

/* Table 2-6 "TDCALL[TDG.VP.VMCALL] Sub-function Completion Status Codes" (returned in R10) from
 * TDX GHCI */
#define TDG_VP_VMCALL_STATUS_SUCCESS     0x0000000000000000
#define TDG_VP_VMCALL_STATUS_RETRY       0x0000000000000001
#define TDG_VP_VMCALL_STATUS_OP_INVALID  0x8000000000000000
#define TDG_VP_VMCALL_STATUS_GPA_INUSE   0x8000000000000001
#define TDG_VP_VMCALL_STATUS_ALIGN_ERROR 0x8000000000000002

/* Direction of TDG.VP.VMCALL<Instruction.IO>, see Table 2-27 */
#define TDG_VP_VMCALL_INSTR_IO_READ  0
#define TDG_VP_VMCALL_INSTR_IO_WRITE 1

/* GetQuote status codes, see Table 3-11 and descriptions in Section 3.3 */
#define TDX_GET_QUOTE_STATUS_SUCCESS     0x0000000000000000
#define TDX_GET_QUOTE_STATUS_IN_FLIGHT   0xFFFFFFFFFFFFFFFF
#define TDX_GET_QUOTE_STATUS_ERROR       0x8000000000000000
#define TDX_GET_QUOTE_STATUS_UNAVAILABLE 0x8000000000000001

/* Table 4.18 from TDX Module ABI (256B in total) */
struct tdx_reportmacstruct {
    uint32_t reporttype;            /* 0x00 -- SGX, 0x81 -- TDX */
    uint8_t  reserved[12];
    uint8_t  cpusvn[16];
    uint8_t  tee_tcb_info_hash[48]; /* SHA384 of TEE_TCB_INFO */
    uint8_t  tee_info_hash[48];     /* SHA384 of TEE_INFO */
    uint8_t  reportdata[64];        /* user-defined data */
    uint8_t  reserved2[32];
    uint8_t  mac[32];               /* MAC over REPORTMACSTRUCT */
} __attribute__((packed));

/* Table 4.20 from TDX Module ABI (512B in total) */
struct tdx_tdinfo_struct {
    uint64_t attributes;         /* TD's attributes */
    uint64_t xfam;               /* TD's eXtended Features Available Mask (same format as XCR0) */
    uint8_t  mrtd[48];           /* measurement of initial contents of TD */
    uint8_t  mrconfigid[48];     /* SW-defined ID for non-owner-defined config of TD */
    uint8_t  mrowner[48];        /* SW-defined ID for the TD's owner */
    uint8_t  mrownerconfig[48];  /* SW-defined ID for owner-defined config of TD */
    uint8_t  rtmr[4][48];        /* array of Run-Time extendable Measurement Registers */
    uint8_t  servtd_hash[48];    /* hash of TDINFO_STRUCTs of service TDs bound to this TD */
    uint8_t  reserved[64];
} __attribute__((packed));

/* Table 4.17 from TDX Module ABI (1024B in total) */
struct tdx_tdreport_struct {
    struct tdx_reportmacstruct reportmacstruct;
    uint8_t tee_tcb_info[239];  /* addit. attestable elements in TD's TCB not reflected in rest */
    uint8_t reserved[17];
    struct tdx_tdinfo_struct tdinfo;
} __attribute__((packed));

/* see Table 3-10 "TDG.VP.VMCALL<GetQuote> format of shared GPA" */
struct tdx_get_quote_format {
    uint64_t version;      /* must be 1; filled by TD */
    uint64_t status_code;  /* one of TDX_GET_QUOTE_STATUS_; filled by VMM */
    uint32_t input_size;   /* size of data from TD (TD Report); filled by TD */
    uint32_t output_size;  /* size of data from VMM (TD Quote); filled by VMM */
    uint8_t  data[0];      /* see tdx_quote.h */
} __attribute__((packed));

/* Registers used as input/output operands for TDCALL leafs, see Tables 2-1 and 2-2 from TDX
 * GHCI and Table 6.276 from TDX Module ABI */
struct tdx_tdcall_regs {
    uint64_t rax, rbx, rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15;
} __attribute__((packed));

long tdx_tdcall(struct tdx_tdcall_regs* regs);

long tdx_vmcall_instr_cpuid(uint64_t eax, uint64_t ecx, uint64_t* out_eax, uint64_t* out_ebx,
                            uint64_t* out_ecx, uint64_t* out_edx);
long tdx_vmcall_instr_hlt(bool interrupt_blocked);
long tdx_vmcall_instr_io(uint64_t access_size, uint64_t direction, uint64_t ioport,
                         uint64_t* data);
long tdx_vmcall_instr_rdmsr(uint64_t msr_index, uint64_t* out_msr_value);
long tdx_vmcall_instr_wrmsr(uint64_t msr_index, uint64_t msr_value);

long tdx_vmcall_ve_reqmmio(uint64_t access_size, uint64_t direction, void* mmio_addr,
                           uint64_t* data);

long tdx_vmcall_gettdvmcallinfo(uint64_t leaf, uint64_t* out_r11, uint64_t* out_r12,
                                uint64_t* out_r13, uint64_t* out_r14);
long tdx_vmcall_mapgpa(uint64_t addr, uint64_t size, uint64_t* out_failed_addr);
long tdx_vmcall_getquote(uint64_t addr, uint64_t size);
long tdx_vmcall_reportfatalerror(uint64_t error_code, uint64_t error_data_addr);
long tdx_vmcall_setupeventnotify(uint64_t interrupt_vector);
long tdx_tdcall_mem_page_accept(uint64_t addr);

long tdx_tdcall_mr_report(uint64_t tdreport_addr, uint64_t tdreport_data_addr);
long tdx_tdcall_mr_rtmr_extend(uint64_t data_addr, uint64_t rtmr_index);

long tdx_tdcall_sys_rd(uint64_t field_id, uint64_t* out_field_value, uint64_t* out_next_field_id);
long tdx_tdcall_sys_rdall(uint64_t metadata_list_addr, uint64_t field_id,
                          uint64_t* out_next_field_id);
long tdx_tdcall_vm_rd(uint64_t field_id, uint64_t* out_field_value, uint64_t* out_next_field_id);
long tdx_tdcall_vm_wr(uint64_t field_id, uint64_t field_value, uint64_t field_value_mask,
                      uint64_t* out_old_field_value);
long tdx_tdcall_vp_rd(uint64_t field_id, uint64_t* out_field_value, uint64_t* out_next_field_id);
long tdx_tdcall_vp_wr(uint64_t field_id, uint64_t field_value, uint64_t field_value_mask,
                      uint64_t* out_old_field_value);

long tdx_tdcall_vp_info(uint8_t* out_gpaw, uint64_t* out_attributes, uint32_t* out_num_vcpus,
                        uint32_t* out_max_vcpus, uint32_t* out_vcpu_index,
                        bool* out_sys_rd_available);
long tdx_tdcall_vp_veinfo_get(uint32_t* out_exit_reason, uint64_t* out_exit_qual,
                              uint64_t* out_guest_linear_addr, uint64_t* out_guest_physical_addr,
                              uint32_t* out_vmexit_instr_length, uint32_t* out_vmexit_instr_info);
long tdx_tdcall_vp_cpuidve_set(bool ve_in_supervisor_mode, bool ve_in_user_mode);
