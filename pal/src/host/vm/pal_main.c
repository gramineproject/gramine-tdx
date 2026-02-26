/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains the main function of the PAL loader, which bootstraps the kernel, loads and
 * processes environment, arguments and manifest.
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "init.h"
#include "list.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_host.h"
#include "pal_internal.h"
#include "pal_rtld.h"
#include "toml.h"
#include "toml_utils.h"

#include "external/fuse_kernel.h"
#include "kernel_apic.h"
#include "kernel_files.h"
#include "kernel_interrupts.h"
#include "kernel_memory.h"
#include "kernel_multicore.h"
#include "kernel_pci.h"
#include "kernel_sched.h"
#include "kernel_syscalls.h"
#include "kernel_time.h"
#include "kernel_virtio.h"
#include "kernel_vmm_inputs.h"
#include "kernel_xsave.h"

uint64_t g_tsc_mhz;

static struct pal_handle* g_first_thread_handle = NULL;

#define FW_CFG_RAM_SIZE 0x03 /* 64-bit RAM size in bytes */
#define FW_CFG_NB_CPUS  0x05 /* 32-bit number of vCPUs */

/* works for little-endian variables of all bit sizes */
static uint64_t rdfwcfg(uint64_t cfg, size_t size) {
    short port; /* unused, added for sanity */
    size_t len; /* unused, added for sanity */
    __asm__ volatile(
        "   out  %w0, %1\n"
        "   inc  %1\n"
        "1: in   %1, %b0\n"
        "   ror  $8, %0\n"
        "   loop 1b\n"
        : "+a"(cfg), "=d"(port), "=c"(len)
        : "1"(FW_CFG_PORT_SEL), "2"(size)
        );
    cfg = cfg >> (8 * (sizeof(uint64_t) - size));
    return cfg;
}

static int tsc_frequency_init(void) {
    uint32_t words[CPUID_WORD_NUM];

    /*
     * We rely on the "invariant TSC" hardware feature (bit CPUID.80000007H:EDX[8]).
     * We also rely on the Generic CPUID space for hypervisors (QEMU/KVM in particular):
     *   - 0x40000000: EAX: The maximum input value for CPUID supported by the hypervisor
     *   - 0x40000010: EAX: (Virtual) TSC frequency in kHz
     */
    _PalCpuIdRetrieve(INVARIANT_TSC_LEAF, 0, words);
    if (!(words[CPUID_WORD_EDX] & (1 << 8))) {
        /* invariant TSC is not available */
        return -PAL_ERROR_DENIED;
    }

    _PalCpuIdRetrieve(0x40000000, 0, words);
    if (words[CPUID_WORD_EAX] < 0x40000010) {
        /* virtual TSC frequency is not available */
        return -PAL_ERROR_DENIED;
    }

    _PalCpuIdRetrieve(0x40000010, 0, words);
    uint64_t tsc_mhz = words[CPUID_WORD_EAX] / 1000;
    if (!tsc_mhz)
        return -PAL_ERROR_DENIED;

    g_tsc_mhz = tsc_mhz;
    return 0;
}

static int switch_apic_to_x2_mode(void) {
    uint32_t words[CPUID_WORD_NUM];
    cpuid(FEATURE_FLAGS_LEAF, 0, words);
    if (!(words[CPUID_WORD_ECX] & (1 << 21))) {
        /* x2APIC mode is not available */
        return -PAL_ERROR_DENIED;
    }

    uint64_t msr = rdmsr(MSR_IA32_APIC_BASE);
    msr |= (1 << 10) + (1 << 11); /* bit 10 -- Enable x2APIC mode; bit 11 -- xAPIC global enable */
    wrmsr(MSR_IA32_APIC_BASE, msr);
    return 0;
}

static int add_preloaded_range(uintptr_t addr, size_t size, const char* comment) {
    return pal_add_initial_range(addr, size, /*pal_prot=*/0, comment);
}

static void zero_out_memory_and_prot_none(void) {
    extern struct pal_initial_mem_range g_initial_mem_ranges[];

    uint64_t cur_mem_range_idx = 0;
    uintptr_t addr = (uintptr_t)g_pal_public_state.memory_address_end;
    while (true) {
        if (!addr)
            return;
        addr -= PAGE_SIZE;

        while (cur_mem_range_idx < g_pal_public_state.initial_mem_ranges_len
                && addr < g_initial_mem_ranges[cur_mem_range_idx].start) {
            /* skip too-high mem ranges; we rely on mem ranges to be sorted in desc order */
            cur_mem_range_idx++;
        }

        while (cur_mem_range_idx < g_pal_public_state.initial_mem_ranges_len
                && addr >= g_initial_mem_ranges[cur_mem_range_idx].start
                && addr <  g_initial_mem_ranges[cur_mem_range_idx].end) {
            /* jump over a mem range; we rely on mem ranges to be sorted in desc order */
            addr = g_initial_mem_ranges[cur_mem_range_idx].start;
            if (!addr)
                return;
            addr -= PAGE_SIZE;
            cur_mem_range_idx++;
        }

        if (addr < (uintptr_t)g_pal_public_state.memory_address_start)
            return;

        memset((void*)addr, 0, PAGE_SIZE);
        int ret = memory_protect((void*)addr, PAGE_SIZE, /*read=*/false, /*write=*/false,
                                 /*execute=*/false);
        if (ret < 0)
            BUG();
    }
}

noreturn static void print_usage_and_exit(void) {
    log_always("USAGE: init <application> args...");
    log_always("This is an internal interface. Use gramine-vm to launch applications.");
    _PalProcessExit(1);
}

noreturn int pal_start_continue(void* cmdline_);

/* called by `vm_bootloader.S` on kernel startup */
__attribute_no_stack_protector  /* starts with zero GS base register */
__attribute_no_sanitize_address /* starts with dummy page tables w/o ASan shared memory */
noreturn void pal_start_c(void) {
    int ret;

    set_dummy_gs_base();

    /* initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set */
    g_pal_public_state.alloc_align = PAGE_SIZE;
    assert(IS_POWER_OF_2(g_pal_public_state.alloc_align));

    uint32_t num_cpus = rdfwcfg(FW_CFG_NB_CPUS, sizeof(uint32_t));
    if (num_cpus < 1 || num_cpus > MAX_NUM_CPUS)
        INIT_FAIL("Detected unsupported number of virtual CPUs: %u (supported: 1..%u)", num_cpus,
                  MAX_NUM_CPUS);

    e820_table_entry e820[E820_NR_ENTRIES]; /* 16*20 = 320B, ok to allocate on stack */
    size_t e820_size;

    ret = e820_table_init((char*)e820, &e820_size, sizeof(e820));
    if (ret < 0)
        INIT_FAIL("Can't read E820 table from VMM");

    ret = memory_init(e820, e820_size, &g_pal_public_state.memory_address_start,
                                       &g_pal_public_state.memory_address_end);
    if (ret < 0)
        INIT_FAIL("Failed to initialize physical memory");

    /* vm_bootloader.S installed tiny page tables that cover [0..32MB) of RAM */
    ret = memory_pagetables_init(g_pal_public_state.memory_address_end,
                                 /*current_page_tables_cover_1gb=*/false);
    if (ret < 0)
        INIT_FAIL("Failed to initialize page tables");

    ret = memory_preload_ranges(e820, e820_size, &add_preloaded_range);
    if (ret < 0)
        INIT_FAIL("Failed to initialize preloaded ranges");

    /* PAL binary is located at 1MB and may occupy until 4MB, see pal.lds */
    /* FIXME: whole PAL binary is RWX because memory_pagetables_init() marked everything as RWX and
     *        zero_out_memory_and_prot_none() did *not* modify perms for PAL binary memory pages */
    ret = add_preloaded_range(0x100000UL, 0x300000UL, "pal_binary");
    if (ret < 0)
        INIT_FAIL("Failed to preload PAL-binary memory range");

    /* Common memory-allocation logic relies on all memory pages to be zeroed out after boot.
     * This is not true for common hypervisors like QEMU/KVM, so must do it ourselves. Also,
     * memory_pagetables_init() marked all pages as RWX, now is good time to revert to NONE. */
    zero_out_memory_and_prot_none();

    call_init_array();

    init_slab_mgr();

    /* must be before apic_init() since the latter uses RDTSC */
    ret = tsc_frequency_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize TSC frequency based on Invariant TSC HW feature");

    ret = time_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize time");

    ret = pci_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize PCI devices");

    /* switching APIC to x2 mode is not done in vm-common code because e.g. Intel TDX boots already
     * with x2APIC enabled, moreover TDX does not allow to access IA32_APIC_BASE MSR at all */
    ret = switch_apic_to_x2_mode();
    if (ret < 0)
        INIT_FAIL("Failed to switch APIC to x2APIC mode");

    ret = apic_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize APIC");

    ret = xsave_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize XSAVE functionality");

    ret = syscalls_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize system call handling");

    /* must be called before interrupts_init() because it allocates interrupt stacks/XSAVE areas */
    ret = init_multicore_prepare(num_cpus);
    if (ret < 0)
        INIT_FAIL("Failed to initialize multicore preparation (per-CPU data and stacks)");

    /* interrupts must be enabled (via `sti`) after all other parts of the kernel are initialized */
    ret = interrupts_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize interrupt/exception handling");

    ret = init_multicore(num_cpus, /*hob_list_addr=*/NULL);
    if (ret < 0)
        INIT_FAIL("Failed to initialize multicore (BSP CPU couldn't init AP CPUs)");

    if (!g_console)
        INIT_FAIL("Failed to initialize virtio-console driver");
    if (!g_fs)
        INIT_FAIL("Failed to initialize virtio-fs driver");

    ret = memory_tighten_permissions();
    if (ret < 0)
        INIT_FAIL("Failed to tighten memory permissions after initialization");

    /* read VMM (untrusted) inputs: gramine args, environment variables and host's PWD from fw_cfg
     * QEMU pseudo-device, see also kernel_vmm_inputs.h */
    ret = cmdline_init_args(g_cmdline, sizeof(g_cmdline));
    if (ret < 0)
        INIT_FAIL("Can't read command line from VMM");

    ret = cmdline_init_envs(g_envs, sizeof(g_envs));
    if (ret < 0)
        INIT_FAIL("Can't read envinronment variables from VMM");

    ret = host_pwd_init();
    if (ret < 0)
        INIT_FAIL("Can't read host's PWD from VMM");

    ret = virtio_fs_fuse_init();
    if (ret < 0)
        INIT_FAIL("Failed FUSE_INIT request of virtio-fs driver");

    ret = _PalThreadCreate(&g_first_thread_handle, pal_start_continue, g_cmdline);
    if (ret < 0)
        INIT_FAIL("Failed to create first thread");

    _PalThreadYieldExecution();  /* we leave this initial stack forever */
    __builtin_unreachable();
}

noreturn int pal_start_continue(void* cmdline_) {
    int ret;

    const char* cmdline = (const char*)cmdline_;

    /* relocate PAL */
    set_pal_binary_name("pal");
    ret = setup_pal_binary(/*apply_relocations=*/true);
    if (ret < 0)
        INIT_FAIL("Relocation of the PAL binary failed");

    /* allocate as global variables in case we overwrite the current stack */
    static int argc = 0;
    static const char* argv[MAX_ARGV_CNT] = { NULL };

    ret = cmdline_read_gramine_args(cmdline, &argc, &argv[0]);
    if (ret < 0)
        INIT_FAIL("Failed to read Gramine arguments");

    static int envp_cnt = 0;
    static const char* envp[MAX_ENVS_CNT] = { NULL };

    ret = cmdline_read_gramine_envs(g_envs, &envp_cnt, &envp[0]);
    if (ret < 0)
        INIT_FAIL("Failed to read host environment variables");

    if (argc < 2)
        print_usage_and_exit();

    bool first_process = !strcmp(argv[0], "init");
    if (!first_process)
        INIT_FAIL("Gramine-VM currently runs only in single-process mode (with `init`)");

    char* manifest_path = alloc_concat(argv[1], -1, ".manifest", -1);
    if (!manifest_path)
        INIT_FAIL("Out of memory");

    char* manifest = NULL;
    ret = read_text_file_to_cstr(manifest_path, &manifest, /*out_size=*/NULL);
    if (ret < 0)
        INIT_FAIL("Reading manifest failed");

    g_pal_common_state.raw_manifest_data = manifest;

    char errbuf[256];
    g_pal_public_state.manifest_root = toml_parse(manifest, errbuf, sizeof(errbuf));
    if (!g_pal_public_state.manifest_root)
        INIT_FAIL_MANIFEST(errbuf);

    ret = toml_bool_in(g_pal_public_state.manifest_root,
                       "sys.enable_extra_runtime_domain_names_conf", /*defaultval=*/false,
                       &g_pal_public_state.extra_runtime_domain_names_conf);
    if (ret < 0)
        INIT_FAIL("Cannot parse 'sys.enable_extra_runtime_domain_names_conf'");

    g_pal_public_state.first_thread = g_first_thread_handle;

    g_pal_public_state.attestation_type = "none";

    ret = pal_common_get_topo_info(&g_pal_public_state.topo_info);
    if (ret < 0)
        INIT_FAIL("Failed to get topology information: %s", pal_strerror(ret));

    pal_main(/*instance_id=*/0, /*parent_process=*/NULL, g_first_thread_handle, argv + 1, envp,
             /*post_callback=*/NULL);
    __builtin_unreachable();
}
