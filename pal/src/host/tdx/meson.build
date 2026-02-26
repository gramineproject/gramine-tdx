pal_tdx_lds = meson.current_source_dir() / 'pal.lds'

pal_tdx_map = custom_target('pal.map[tdx]',
    command: [gen_pal_map_prog, '@INPUT@', '@OUTPUT@'],
    input: ['../../pal_symbols', 'pal.map.template'],
    output: 'pal.map',
)

pal_tdx_sources = files(
    'pal_bootloader.S',

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

    'tdx_tdcall.S',
    'tdx_arch.c',

    'vm_callbacks.c',
)

libpal_tdx = executable('pal',
    pal_tdx_sources,
    pal_vm_common_sources,
    pal_vm_common_tdx_sources,
    pal_vm_common_asm_offsets_h,
    pal_common_sources,

    include_directories: [
        includes_pal_common,
        pal_vm_common_inc,
        include_directories('.'),
    ],

    c_args: [
        cflags_pal_common,
        '-DHOST_TYPE=TDX',

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
        '-Wl,--version-script=@0@'.format(pal_tdx_map.full_path()),
        '-Wl,-T@0@'.format(pal_tdx_lds),
        '-Wl,--eh-frame-hdr',
    ],

    pie: true,

    # by default, compilers don't export symbols for executables, revert this behavior
    export_dynamic: true,

    link_depends: [
        pal_tdx_map,
        pal_tdx_lds,
    ],

    dependencies: [
        common_dep,
        cryptoadapter_dep,
    ],

    install: true,
    install_dir: pkglibdir / 'tdx',
)

# FIXME: TD-shim should be installed somewhere global
meson.add_install_script('/bin/sh', '-c',
    ('cd "$HOME"/td-shim && cargo run -p td-shim-tools --bin td-shim-ld -- ' +
     'target/x86_64-unknown-none/release/ResetVector.bin ' +
     'target/x86_64-unknown-none/release/td-shim ' +
     '-t executable -p "$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/tdx/pal ' +
     '-o "$MESON_INSTALL_DESTDIR_PREFIX"/@0@/gramine/tdx/tdshim-pal').format(get_option('libdir')))

libpal_tdx_dep = declare_dependency(
    link_with: libpal_tdx,
)

if debug
    custom_target('libpal.so.map',
        input: libpal_tdx,
        command: gen_symbol_map_cmd,
        capture: true,
        output: 'libpal.so.map',

        install: true,
        install_dir: pkglibdir / 'tdx',
    )
endif
