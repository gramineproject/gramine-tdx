/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains the main function of the PAL loader, which bootstraps the kernel, loads and
 * processes environment, arguments and manifest.
 */

#include <stdint.h>

#include "api.h"
#include "cpu.h"
#include "crypto.h"
#include "list.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_common_tf.h"
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
#include "kernel_pci.h"
#include "kernel_sched.h"
#include "kernel_syscalls.h"
#include "kernel_time.h"
#include "kernel_virtio.h"
#include "kernel_vmm_inputs.h"
#include "kernel_xsave.h"
#include "tdx_arch.h"
#include "tdx_hob.h"

uint64_t g_tsc_mhz;

static struct pal_handle* g_first_thread_handle = NULL;
static struct pal_handle* g_idle_thread_handle = NULL;
static struct pal_handle* g_bottomhalves_thread_handle = NULL;

static uint64_t g_shared_bit;

static int memory_mark_pages_shared(uint64_t addr, size_t size) {
    uint64_t mark_addr = addr;
    while (mark_addr < addr + size) {
        uint64_t* pte_addr;
        int ret = memory_find_page_table_entry(mark_addr, &pte_addr);
        if (ret < 0)
            return ret;

        *pte_addr |= g_shared_bit;
        invlpg(mark_addr);

        mark_addr += PRESET_PAGESIZE;
    }
    return 0;
}

static int shared_memory_init(uint64_t gpa_width) {
    g_shared_bit = 1UL << (gpa_width - 1);

    long ret = memory_mark_pages_shared(SHARED_MEM_ADDR, SHARED_MEM_SIZE);
    if (ret < 0)
        return ret;

    ret = TDG_VP_VMCALL_STATUS_RETRY;
    uint64_t map_addr = SHARED_MEM_ADDR;
    uint64_t map_size = SHARED_MEM_SIZE;

    while (ret == TDG_VP_VMCALL_STATUS_RETRY) {
        uint64_t failed_addr = 0;
        long ret = tdx_vmcall_mapgpa(g_shared_bit | map_addr, map_size, &failed_addr);
        if (ret != TDG_VP_VMCALL_STATUS_RETRY) {
            /* done */
            break;
        }
        if (!(map_addr <= failed_addr && failed_addr < map_addr + map_size)) {
            /* sanity check, just in case */
            return -PAL_ERROR_DENIED;
        }
        map_size -= failed_addr - map_addr;
        map_addr = failed_addr;
    }

    return ret;
}

static int tsc_frequency_init(void) {
    uint32_t words[CPUID_WORD_NUM];

    /*
     * We rely on the "invariant TSC" hardware feature (bit CPUID.80000007H:EDX[8]).  We also rely
     * on Time Stamp Counter and Nominal Core Crystal Clock Info leaf that is always available in
     * Intel TDX.
     */
    _PalCpuIdRetrieve(TSC_FREQ_LEAF, 0, words);
    if (!words[CPUID_WORD_EAX] || !words[CPUID_WORD_EBX]) {
        /* Intel TDX guarantees that EAX = 1 and EBX = 0x017D7840; this check is a precaution */
        return -PAL_ERROR_DENIED;
    }

    if (!words[CPUID_WORD_ECX]) {
        /* ECX is taken from host VMM's TSC_FREQUENCY parameter; a benign VMM always sets it */
        return -PAL_ERROR_DENIED;
    }

    /* calculate TSC frequency as core crystal clock frequency (EAX) * EBX / EAX; cast to 64-bit
     * first to prevent integer overflow */
    uint64_t ecx_hz = words[CPUID_WORD_ECX];
    uint64_t g_tsc_hz = ecx_hz * words[CPUID_WORD_EBX] / words[CPUID_WORD_EAX];
    g_tsc_mhz = g_tsc_hz / 1000000;
    return 0;
}

static int add_preloaded_range(uintptr_t addr, size_t size, const char* comment) {
    /* FIXME: use proper prot flags for preloaded (excluded from memory allocation) ranges? */
    return pal_add_initial_range(addr, size, /*pal_prot=*/0, comment);
}

static int tdx_extend_rtmr2_with_loader_entrypoint(void) {
    assert(g_pal_public_state.manifest_root);

    int ret;
    __attribute__((aligned(64))) uint8_t rtmr2_buffer[48] = {0};

    char* loader_entrypoint_uri = NULL;
    char* loader_entrypoint_contents = NULL;
    size_t loader_entrypoint_contents_size = 0;

    ret = toml_string_in(g_pal_public_state.manifest_root, "loader.entrypoint",
                         &loader_entrypoint_uri);
    if (ret < 0) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (!loader_entrypoint_uri || !strstartswith(loader_entrypoint_uri, URI_PREFIX_FILE)) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    ret = read_text_file_to_cstr(loader_entrypoint_uri + static_strlen(URI_PREFIX_FILE),
                                 &loader_entrypoint_contents, &loader_entrypoint_contents_size);
    if (ret < 0)
        goto out;
    if (!loader_entrypoint_contents || !loader_entrypoint_contents_size) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* FIXME: replace with SHA384 when our common code exports it */
    LIB_SHA256_CONTEXT sha;
    ret = lib_SHA256Init(&sha);
    if (ret < 0)
        goto out;
    ret = lib_SHA256Update(&sha, (uint8_t*)loader_entrypoint_contents,
                           loader_entrypoint_contents_size);
    if (ret < 0)
        goto out;
    ret = lib_SHA256Final(&sha, rtmr2_buffer);
    if (ret < 0)
        goto out;

    long tdx_ret = tdx_tdcall_mr_rtmr_extend((uint64_t)&rtmr2_buffer, /*rtmr_index=*/2);
    if (tdx_ret) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    ret = 0;
out:
    free(loader_entrypoint_uri);
    free(loader_entrypoint_contents);
    return ret;
}

noreturn static void print_usage_and_exit(void) {
    log_always("USAGE: init <application> args...");
    log_always("This is an internal interface. Use gramine-tdx to launch applications.");
    _PalProcessExit(1);
}

noreturn int pal_start_continue(void* cmdline_);

/*
 * C entry, called by `pal_bootloader.S` on kernel startup:
 *   - RDI: holds the payload HOB address
 *   - RSI: holds the address where the payload is loaded
 */
noreturn void pal_start_c(void* hob_addr, void* this_addr) {
    __UNUSED(this_addr);

    int ret;

    wrmsr(MSR_IA32_GS_BASE, 0x0); /* just for sanity: no current-thread TCB at init */

    /* initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set */
    g_pal_public_state.alloc_align = PRESET_PAGESIZE;
    assert(IS_POWER_OF_2(g_pal_public_state.alloc_align));

    uint64_t gpa_width = 0;
    for (EFI_HOB_GENERIC_HEADER* hob = hob_addr; !END_OF_HOB_LIST(hob); hob = GET_NEXT_HOB(hob)) {
        if (GET_HOB_TYPE(hob) == EFI_HOB_TYPE_CPU) {
            EFI_HOB_CPU* cpu_hob = (EFI_HOB_CPU*)hob;
            gpa_width = cpu_hob->SizeOfMemorySpace;
        }
    }

    if (gpa_width != 48 && gpa_width != 52)
        INIT_FAIL("Failed to determine GPAW (allowed values are 48 and 52)");

    EFI_HOB_E820_TABLE* e820_hob = NULL;
    for (EFI_HOB_GENERIC_HEADER* hob = hob_addr; !END_OF_HOB_LIST(hob); hob = GET_NEXT_HOB(hob)) {
        if (GET_HOB_TYPE(hob) == EFI_HOB_TYPE_GUID_EXTENSION) {
            EFI_HOB_GUID_TYPE* ext_hob = (EFI_HOB_GUID_TYPE*)hob;
            if (HOB_GUID_EQUAL(&ext_hob->Name, &EFI_HOB_E820_TABLE_GUID)) {
                e820_hob = (EFI_HOB_E820_TABLE*)ext_hob;
                break;
            }
        }
    }

    if (!e820_hob)
        INIT_FAIL("Failed to find E820 hob for memory initialization");

    /* HobLength is always a multiple of 8B, but each entry in E820_TABLE_ENTRY is 20B
     * in size, so HobLength may be larger than the total size of the e820 table */
    uint16_t e820_table_size;
    e820_table_size = GET_HOB_LENGTH(e820_hob) - offsetof(EFI_HOB_E820_TABLE, E820Table);
    e820_table_size -= e820_table_size % sizeof(E820_TABLE_ENTRY);

    ret = memory_init((e820_table_entry*)e820_hob->E820Table, e820_table_size,
                      &g_pal_public_state.memory_address_start,
                      &g_pal_public_state.memory_address_end);
    if (ret < 0)
        INIT_FAIL("Failed to initialize physical memory");

    ret = memory_pagetables_init(g_pal_public_state.memory_address_end);
    if (ret < 0)
        INIT_FAIL("Failed to initialize page tables");

    ret = memory_preload_ranges((e820_table_entry*)e820_hob->E820Table, e820_table_size,
                                &add_preloaded_range);
    if (ret < 0)
        INIT_FAIL("Failed to initialize preloaded ranges");

    ret = shared_memory_init(gpa_width);
    if (ret < 0)
        INIT_FAIL("Failed to initialize shared TDX memory");

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

    ret = apic_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize APIC");

    ret = xsave_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize XSAVE functionality");

    ret = syscalls_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize system call handling");

    /* interrupts must be enabled (via `sti`) after all other parts of the kernel are initialized */
    ret = interrupts_init();
    if (ret < 0)
        INIT_FAIL("Failed to initialize interrupt/exception handling");

    if (!g_console)
        INIT_FAIL("Failed to initialize virtio-console driver");
    if (!g_fs)
        INIT_FAIL("Failed to initialize virtio-fs driver");

    /* read VMM (untrusted) inputs: gramine args and host's PWD from fw_cfg QEMU pseudo-device,
     * see also kernel_vmm_inputs.h */
    char cmdline[512] = {0};
    ret = cmdline_init(cmdline, sizeof(cmdline));
    if (ret < 0)
        INIT_FAIL("Can't read command line from VMM");

    ret = host_pwd_init();
    if (ret < 0)
        INIT_FAIL("Can't read host's PWD from VMM");

    ret = virtio_fs_fuse_init();
    if (ret < 0)
        INIT_FAIL("Failed FUSE_INIT request of virtio-fs driver");

    ret = _PalThreadCreate(&g_idle_thread_handle, thread_idle_run, NULL);
    if (ret < 0)
        INIT_FAIL("Failed to create idle thread");

    ret = _PalThreadCreate(&g_bottomhalves_thread_handle, thread_bottomhalves_run, NULL);
    if (ret < 0)
        INIT_FAIL("Failed to create bottomhalves thread");

    ret = _PalThreadCreate(&g_first_thread_handle, pal_start_continue, cmdline);
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
    ret = setup_pal_binary(/*apply_relocations=*/false);
    if (ret < 0)
        INIT_FAIL("Relocation of the PAL binary failed");

    /* allocate as global variables in case we overwrite the current stack */
    static int argc = 0;
    static const char* argv[MAX_ARGV] = { NULL };
    static const char* envp[1] = { NULL };

    ret = cmdline_read_gramine_args(cmdline, &argc, &argv[0]);
    if (ret < 0)
        INIT_FAIL("Failed to read Gramine arguments");

    if (argc < 2)
        print_usage_and_exit();

    bool first_process = !strcmp(argv[0], "init");
    if (!first_process)
        INIT_FAIL("Gramine-TDX currently runs only in single-process mode (with `init`)");

    /* hack to re-use .manifest.sgx file if .manifest.tdx not found */
    char* manifest_path_tdx = alloc_concat(argv[1], -1, ".manifest.tdx", -1);
    if (!manifest_path_tdx)
        INIT_FAIL("Out of memory");

    char* manifest_path_sgx = alloc_concat(argv[1], -1, ".manifest.sgx", -1);
    if (!manifest_path_sgx)
        INIT_FAIL("Out of memory");

    char* manifest = NULL;
    ret = read_text_file_to_cstr(manifest_path_tdx, &manifest, /*out_size=*/NULL);
    if (ret == -PAL_ERROR_STREAMNOTEXIST)
        ret = read_text_file_to_cstr(manifest_path_sgx, &manifest, /*out_size=*/NULL);
    if (ret < 0)
        INIT_FAIL("Reading manifest failed (tried .manifest.tdx and .manifest.sgx extensions)");

    g_pal_common_state.raw_manifest_data = manifest;

    char errbuf[256];
    g_pal_public_state.manifest_root = toml_parse(manifest, errbuf, sizeof(errbuf));
    if (!g_pal_public_state.manifest_root)
        INIT_FAIL_MANIFEST(errbuf);

    /*
     * TD-Shim already extended RTMR[0] and RTMR[1] with TD-Shim configuration and the payload (this
     * PAL binary) respectively. Gramine extends RTMR[2] with LibOS (more specifically, with
     * `loader.entrypoint`) measurement. This measurement is calculated as follows: take SHA256 hash
     * over the contents of the `loader.entrypoint` binary, then feed it as input to rtmr-extend
     * TDX operation (it will perform SHA384 over [prev_rtmr_value_in_first_48bits +
     * input_in_next_48bits]).
     *
     * FIXME: Alternatively, Gramine could extend RTMR[2] with the manifest file measurement. Since
     *        the manifest contains hashes of LibOS binary and all other binaries, this may be a
     *        better measurement input.
     */
    ret = tdx_extend_rtmr2_with_loader_entrypoint();
    if (ret < 0)
        INIT_FAIL("Failed to extend TDX RTMR2 with `loader.entrypoint` binary: %s",
                  pal_strerror(ret));

    ret = toml_bool_in(g_pal_public_state.manifest_root,
                       "sys.enable_extra_runtime_domain_names_conf", /*defaultval=*/false,
                       &g_pal_public_state.extra_runtime_domain_names_conf);
    if (ret < 0)
        INIT_FAIL("Cannot parse 'sys.enable_extra_runtime_domain_names_conf'");

    g_pal_public_state.first_thread = g_first_thread_handle;

    g_pal_public_state.attestation_type = "dcap";

    ret = pal_common_get_topo_info(&g_pal_public_state.topo_info);
    if (ret < 0)
        INIT_FAIL("Failed to get topology information: %s", pal_strerror(ret));

    ret = init_file_check_policy();
    if (ret < 0)
        INIT_FAIL("Failed to load the file check policy: %s", pal_strerror(ret));

    ret = init_allowed_files();
    if (ret < 0)
        INIT_FAIL("Failed to initialize allowed files: %s", pal_strerror(ret));

    ret = init_trusted_files();
    if (ret < 0)
        INIT_FAIL("Failed to initialize trusted files: %s", pal_strerror(ret));

    g_use_trusted_files = true;

    pal_main(/*instance_id=*/0, /*parent_process=*/NULL, g_first_thread_handle, argv + 1, envp,
             /*post_callback=*/NULL);
    __builtin_unreachable();
}
