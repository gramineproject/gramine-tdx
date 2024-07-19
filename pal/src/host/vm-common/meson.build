pal_vm_common_sources = files(
    'kernel_events.S',
    'kernel_static_structs.S',

    'kernel_acpi_madt.c',
    'kernel_apic.c',
    'kernel_debug.c',
    'kernel_files.c',
    'kernel_interrupts.c',
    'kernel_memory.c',
    'kernel_multicore.c',
    'kernel_pci.c',
    'kernel_sched.c',
    'kernel_syscalls.c',
    'kernel_thread.c',
    'kernel_time.c',
    'kernel_virtio.c',
    'kernel_virtio_console.c',
    'kernel_virtio_fs.c',
    'kernel_virtio_vsock.c',
    'kernel_vmm_inputs.c',
    'kernel_xsave.c',
    'pal_common_console.c',
    'pal_common_eventfd.c',
    'pal_common_events.c',
    'pal_common_exception.c',
    'pal_common_files.c',
    'pal_common_misc.c',
    'pal_common_object.c',
    'pal_common_pipes.c',
    'pal_common_sockets.c',
    'pal_common_tf.c',
    'pal_common_threading.c',

    'external/realpath.c',
)

pal_vm_common_nontdx_sources = files(
    'kernel_multicore.S',
)

pal_vm_common_tdx_sources = files(
    'kernel_multicore64.S',
)

pal_vm_common_inc = [
    includes_pal_common,
    include_directories(
        '.',
        '../vm',
        '../../../include/arch/@0@/vm'.format(host_machine.cpu_family()),
        '../../../include/host/linux-common', # virtio-fs driver uses Linux flags
    ),
]

pal_vm_common_generated_offsets_print = executable('pal-vm-generated-generated-offsets-print',
    'generated_offsets.c',
    generated_offsets_print_src,
    include_directories: pal_vm_common_inc,
    c_args: cflags_pal_common,
)

pal_vm_common_asm_offsets_h = custom_target('asm-offsets.h[pal-vm]',
    command: [pal_vm_common_generated_offsets_print, '--h'],
    capture: true,
    output: 'asm-offsets.h',
)
