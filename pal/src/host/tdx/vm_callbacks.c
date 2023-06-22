/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * VM callbacks notes:
 *
 * - All shared-memory, MSR, MMIO and IO-ports accesses are double-checked (whether they access
 *   allowed memory regions/registers/port numbers). This may hamper performance but provides
 *   improved security.
 */

#include <stdint.h>

#include "kernel_apic.h"
#include "kernel_debug.h"
#include "kernel_interrupts.h"
#include "kernel_memory.h"
#include "kernel_pci.h"
#include "kernel_vmm_inputs.h"
#include "tdx_arch.h"
#include "vm_callbacks.h"

static inline void check_shared_memory_access(uintptr_t addr, size_t size) {
    if (!(SHARED_MEM_ADDR <= addr && addr + size <= SHARED_MEM_ADDR + SHARED_MEM_SIZE)) {
        /* memory to access is not completely inside shared memory */
        BUG();
    }
}

static inline void check_mmio_access(uintptr_t addr, size_t size) {
    if (!(PCI_MMIO_START_ADDR <= addr && addr + size <= PCI_MMIO_END_ADDR) &&
            !(IOAPIC_ADDR <= addr && addr + size <= IOAPIC_ADDR + IOAPIC_SIZE)) {
        /* memory to access is not completely inside allowed MMIO/IOAPIC regions */
        BUG();
    }
}

static inline void check_portio_read(uint16_t port) {
    if (port != PCI_CONFIG_SPACE_DATA_IO_PORT &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT + 1 &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT + 2 &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT + 3 &&
            port != FW_CFG_PORT_SEL + 1) {
        /* not a known port to be read */
        BUG();
    }
}

static inline void check_portio_write(uint16_t port) {
    if (port != PCI_CONFIG_SPACE_ADDR_IO_PORT &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT + 1 &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT + 2 &&
            port != PCI_CONFIG_SPACE_DATA_IO_PORT + 3 &&
            port != FW_CFG_PORT_SEL &&
            port != SERIAL_IO_PORT) {
        /* not a known port to be written */
        BUG();
    }
}

void* vm_shared_memcpy(void* _dest, const void* _src, size_t n) {
    uintptr_t dest = (uintptr_t)_dest;
    uintptr_t src  = (uintptr_t)_src;
    if (SHARED_MEM_ADDR <= src && src + n <= SHARED_MEM_ADDR + SHARED_MEM_SIZE) {
        if (dest < SHARED_MEM_ADDR + SHARED_MEM_SIZE && SHARED_MEM_ADDR < dest + n) {
            /* copying from shared memory into TD memory, but `dest` overlaps shared memory */
            BUG();
        }
    } else if (SHARED_MEM_ADDR <= dest && dest + n <= SHARED_MEM_ADDR + SHARED_MEM_SIZE) {
        if (src < SHARED_MEM_ADDR + SHARED_MEM_SIZE && SHARED_MEM_ADDR < src + n) {
            /* copying from TD memory into shared memory, but `src` overlaps shared memory */
            BUG();
        }
    } else {
        /* neither `src` nor `dest` is completely within shared memory */
        BUG();
    }

    return memcpy(_dest, _src, n);
}

void* vm_shared_memset(void* _s, int c, size_t n) {
    uintptr_t s = (uintptr_t)_s;
    if (!(SHARED_MEM_ADDR <= s && s + n <= SHARED_MEM_ADDR + SHARED_MEM_SIZE)) {
        /* memory to memset is not completely inside shared memory */
        BUG();
    }

    return memset(_s, c, n);
}

void vm_shared_wrmsr(uint64_t msr, uint64_t value) {
    if (msr != MSR_INSECURE_IA32_LAPIC_SPURIOUS_INTERRUPT_VECTOR &&
            msr != MSR_INSECURE_IA32_LAPIC_LVT_TIMER &&
            msr != MSR_INSECURE_IA32_TSC_DEADLINE) {
        /* not a known insecure MSR */
        BUG();
    }

    int ret = tdx_vmcall_instr_wrmsr(msr, value);
    if (ret < 0)
        BUG();
}

uint8_t vm_shared_readb(uint8_t* shared_addr) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    return READ_ONCE(*shared_addr);
}

uint16_t vm_shared_readw(uint16_t* shared_addr) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    return READ_ONCE(*shared_addr);
}

uint32_t vm_shared_readl(uint32_t* shared_addr) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    return READ_ONCE(*shared_addr);
}

uint64_t vm_shared_readq(uint64_t* shared_addr) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    return READ_ONCE(*shared_addr);
}

void vm_shared_writeb(uint8_t* shared_addr, uint8_t data) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

void vm_shared_writew(uint16_t* shared_addr, uint16_t data) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

void vm_shared_writel(uint32_t* shared_addr, uint32_t data) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

void vm_shared_writeq(uint64_t* shared_addr, uint64_t data) {
    check_shared_memory_access((uintptr_t)shared_addr, sizeof(*shared_addr));
    WRITE_ONCE(*shared_addr, data);
    COMPILER_BARRIER();
}

uint8_t vm_mmio_readb(uint8_t* mmio_addr) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_READ,
                          mmio_addr, &data);
    return (uint8_t)data;
}

uint16_t vm_mmio_readw(uint16_t* mmio_addr) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_READ,
                          mmio_addr, &data);
    return (uint16_t)data;
}

uint32_t vm_mmio_readl(uint32_t* mmio_addr) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_READ,
                          mmio_addr, &data);
    return (uint32_t)data;
}

uint64_t vm_mmio_readq(uint64_t* mmio_addr) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_READ,
                          mmio_addr, &data);
    return data;
}

void vm_mmio_writeb(uint8_t* mmio_addr, uint8_t _data) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data = (uint64_t)_data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_WRITE,
                          mmio_addr, &data);
}

void vm_mmio_writew(uint16_t* mmio_addr, uint16_t _data) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data = (uint64_t)_data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_WRITE,
                          mmio_addr, &data);
}

void vm_mmio_writel(uint32_t* mmio_addr, uint32_t _data) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    uint64_t data = (uint64_t)_data;
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_WRITE,
                          mmio_addr, &data);
}

void vm_mmio_writeq(uint64_t* mmio_addr, uint64_t data) {
    check_mmio_access((uintptr_t)mmio_addr, sizeof(*mmio_addr));
    tdx_vmcall_ve_reqmmio(sizeof(*mmio_addr), TDG_VP_VMCALL_INSTR_IO_WRITE,
                          mmio_addr, &data);
}

uint8_t vm_portio_readb(uint16_t port) {
    check_portio_read(port);
    uint64_t data;
    tdx_vmcall_instr_io(sizeof(uint8_t), TDG_VP_VMCALL_INSTR_IO_READ, port, &data);
    return (uint8_t)data;
}

uint16_t vm_portio_readw(uint16_t port) {
    check_portio_read(port);
    uint64_t data;
    tdx_vmcall_instr_io(sizeof(uint16_t), TDG_VP_VMCALL_INSTR_IO_READ, port, &data);
    return (uint16_t)data;
}

uint32_t vm_portio_readl(uint16_t port) {
    check_portio_read(port);
    uint64_t data;
    tdx_vmcall_instr_io(sizeof(uint32_t), TDG_VP_VMCALL_INSTR_IO_READ, port, &data);
    return (uint32_t)data;
}

void vm_portio_writeb(uint16_t port, uint8_t val) {
    check_portio_write(port);
    uint64_t data = (uint64_t)val;
    tdx_vmcall_instr_io(sizeof(val), TDG_VP_VMCALL_INSTR_IO_WRITE, port, &data);
}

void vm_portio_writew(uint16_t port, uint16_t val) {
    check_portio_write(port);
    uint64_t data = (uint64_t)val;
    tdx_vmcall_instr_io(sizeof(val), TDG_VP_VMCALL_INSTR_IO_WRITE, port, &data);
}

void vm_portio_writel(uint16_t port, uint32_t val) {
    check_portio_write(port);
    uint64_t data = (uint64_t)val;
    tdx_vmcall_instr_io(sizeof(val), TDG_VP_VMCALL_INSTR_IO_WRITE, port, &data);
}

int vm_virtualization_exception(struct isr_regs* regs) {
    uint32_t exit_reason;
    uint64_t exit_qual;
    uint64_t guest_linear_addr;
    uint64_t guest_physical_addr;
    uint32_t vmexit_instr_length;
    uint32_t vmexit_instr_info;

    int ret = tdx_tdcall_vp_veinfo_get(&exit_reason, &exit_qual, &guest_linear_addr,
                                       &guest_physical_addr, &vmexit_instr_length,
                                       &vmexit_instr_info);
    if (ret < 0)
        return ret;

    /* basic exit reasons, see Intel SDM, Vol. 3, Appendix C */
    switch (exit_reason) {
        case 10: /* CPUID */
            if (regs->rax == 0x2) {
                /* TLB/Cache/Prefetch info: dummy values from Intel SDM, Vol. 2, Example 3-1 */
                regs->rax = 0x665b5001;
                regs->rbx = 0x0;
                regs->rcx = 0x0;
                regs->rdx = 0x7a7000;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x5) {
                /* MONITOR/MWAIT -- hard-code values from real CPU */
                regs->rax = 0x00000040;
                regs->rbx = 0x00000040;
                regs->rcx = 0x00000003;
                regs->rdx = 0x00001020;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x6) {
                /* Thermal and Power Management -- hard-code values from real CPU */
                regs->rax = 0x00450ef7;
                regs->rbx = 0x00000002;
                regs->rcx = 0x00000009;
                regs->rdx = 0x00000000;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x7) {
                /* Structured Extended Feature Enumeration -- Intel TDX reports subleaves 0x0 and
                 * 0x1 but not any other (all-zeros) leaves */
                if (regs->rcx > 0x1) {
                    regs->rax = regs->rbx = regs->rcx = regs->rdx = 0x00000000;
                    regs->rip += vmexit_instr_length;
                    return 0;
                }
            } else if (regs->rax == 0xb) {
                /* Extended Topology Enumeration -- hard-code a single-core system */
                if (regs->rcx == 0x0) {
                    /* level: SMT */
                    regs->rax = 0x00000001; /* number of bits to shift right on x2APIC ID */
                    regs->rbx = 0x00000001; /* number of logical processors at this level type */
                    regs->rcx = 0x00000100; /* bits 15-08: level type, bits 07-00: same as rcx */
                    regs->rdx = 0x00000000; /* x2APIC ID of current logical processor */
                } else if (regs->rcx == 0x1) {
                    /* level: Core */
                    regs->rax = 0x00000007; /* number of bits to shift right on x2APIC ID; dummy */
                    regs->rbx = 0x00000001; /* number of logical processors at this level type */
                    regs->rcx = 0x00000201; /* bits 15-08: level type, bits 07-00: same as rcx */
                    regs->rdx = 0x00000000; /* x2APIC ID of current logical processor */
                } else {
                    /* level: unknown */
                    regs->rax = regs->rbx = 0x00000000; /* for invalid level type, all zeros */
                    /* bits 15-08: invalid level type, bits 07-00: same as rcx */
                    regs->rcx = 0x00000000 | regs->rcx;
                    regs->rdx = 0x00000000; /* x2APIC ID of current logical processor */
                }
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x80000002) {
                /* Processor Brand String -- we hard-code "Intel(R) Xeon(R) Platinum 8480CTDX" */
                regs->rax = 0x65746e49;
                regs->rbx = 0x2952286c;
                regs->rcx = 0x6f655820;
                regs->rdx = 0x2952286e;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x80000003) {
                /* Processor Brand String continued */
                regs->rax = 0x616c5020;
                regs->rbx = 0x756e6974;
                regs->rcx = 0x3438206d;
                regs->rdx = 0x54433038;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x80000004) {
                /* Processor Brand String continued */
                regs->rax = 0x00005844;
                regs->rbx = 0x00000000;
                regs->rcx = 0x00000000;
                regs->rdx = 0x00000000;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x80000005) {
                /* Reserved -- all zeros */
                regs->rax = regs->rbx = regs->rcx = regs->rdx = 0x00000000;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x80000006) {
                /* Cache info -- we hard-code dummy (taken from one SPR machine) */
                regs->rax = regs->rbx = regs->rdx = 0x00000000;
                regs->rcx = 0x08007040;
                regs->rip += vmexit_instr_length;
                return 0;
            } else if (regs->rax == 0x80000007) {
                regs->rax = 0;
                regs->rbx = 0;
                regs->rcx = 0;
                regs->rdx = 1U << 8; /* invariant TSC available */
                regs->rip += vmexit_instr_length;
                return 0;
            }
            return -PAL_ERROR_DENIED;

        default: /* unsupported exit reason */
            return -PAL_ERROR_DENIED;
    }

    return 0;
}