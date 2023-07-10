pal_vm_bios_lds = meson.current_source_dir() / 'bios' / 'bios.lds'
pal_vm_bios_src = meson.current_source_dir() / 'bios' / 'bios.S'

libpal_vm_bios = executable('bios',
    pal_vm_bios_src,

    link_args: [
        '-nostdlib',
        '-static',
        '-Wl,-T@0@'.format(pal_vm_bios_lds),
    ],
    link_depends: pal_vm_bios_lds,

    install: true,
    install_dir: pkglibdir / 'vm',
)

pal_vm_lds = meson.current_source_dir() / 'pal.lds'

pal_vm_map = custom_target('pal.map[vm]',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal_symbols', 'pal.map.template'],
    output: 'pal.map',
)

pal_vm_sources = files(
    'pal_console.c',
    'pal_devices.c',
    'pal_eventfd.c',
    'pal_events.c',
    'pal_exception.c',
    'pal_files.c',
    'pal_main.c',
    'pal_memory.c',
    'pal_misc.c',
    'pal_object.c',
    'pal_pipes.c',
    'pal_process.c',
    'pal_rtld.c',
    'pal_sockets.c',
    'pal_streams.c',
    'pal_threading.c',

    'vm_bootloader.S',
    'vm_callbacks.c',
)

libpal_vm = executable('pal',
    pal_vm_sources,
    pal_vm_common_sources,
    pal_vm_common_asm_offsets_h,
    pal_common_sources,

    include_directories: [
        includes_pal_common,
        pal_vm_common_inc,
        include_directories('.'),
    ],

    c_args: [
        cflags_pal_common,
        '-DHOST_TYPE=VM',

        # instruct GCC not to use the AMD64 ABI 128B redzone which resides below the stack pointer,
        # or kernel will be interrupt unsafe (https://wiki.osdev.org/Creating_a_64-bit_kernel)
        '-mno-red-zone',

        '-Wno-address-of-packed-member',

        cflags_custom_stack_protector,

        # cflags_sanitizers,
    ],

    link_args: [
        '-nostdlib',

        # For PAL symbol resolution, we use old-style hash (DT_HASH) table instead of the
        # default GNU hash (DT_GNU_HASH) table -- to figure out the number of dynamic symbols in
        # the SYMTAB symbol table
        '-Wl,--hash-style=sysv',

        # Generic PAL binary verification in pal_rtld.c requires DT_SONAME
        '-Wl,-soname=libpal.so',

        # PAL is expected to be linked with RELRO (Relocation Read-Only)
        '-Wl,-zrelro',
        '-Wl,-znow',

        '-Wl,-zcombreloc',
        '-Wl,-zdefs',
        '-Wl,--version-script=@0@'.format(pal_vm_map.full_path()),
        '-Wl,-T@0@'.format(pal_vm_lds),
        '-Wl,--eh-frame-hdr',
    ],

    pie: true,

    # by default, compilers don't export symbols for executables, revert this behavior
    export_dynamic: true,

    link_depends: [
        pal_vm_map,
        pal_vm_lds,
    ],

    dependencies: [
        common_dep,
        cryptoadapter_dep,
    ],

    install: true,
    install_dir: pkglibdir / 'vm',
)

libpal_vm_dep = declare_dependency(
    link_with: libpal_vm,
)

if debug
    custom_target('libpal.so.map',
        input: libpal_vm,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'libpal.so.map',

        install: true,
        install_dir: pkglibdir / 'vm',
    )
endif
