/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Read inputs from VMM. Currently two inputs:
 * - Command-line arguments
 * - PWD (host's current working directory)
 *
 * Gramine command-line args are read from fw_cfg QEMU pseudo-device. They are supposed to be put in
 * one of the selectors above 0x19 and be in a special format (see below). The selector with
 * command-line args has the name "opt/gramine/cmdline". For details, see:
 *   - qemu.org/docs/master/specs/fw_cfg.html
 *   - wiki.osdev.org/QEMU_fw_cfg
 *
 * The arguments must be in the following format:
 *    "-gramine init argv0 argv1 ... -gramine-end"
 */

#pragma once

#include "kernel_files.h"

#define FW_CFG_PORT_SEL   0x510
#define FW_CFG_FILE_DIR   0x19

#define GRAMINE_ARGS_BEGIN_STR "-gramine"
#define GRAMINE_ARGS_END_STR "-gramine-end"

#define MAX_ARGV 128
#define MAX_FW_CFG_FILES 512 /* QEMU fw cfg doesn't specify a limit, but let's set it for sanity */

/* taken from QEMU's fw_cfg.h */
struct FWCfgFile {          /* an individual file entry, 64 bytes total */
    uint32_t size;          /* size of referenced fw_cfg item, big-endian */
    uint16_t select;        /* selector key of fw_cfg item, big-endian */
    uint16_t reserved;
    char name[56];          /* fw_cfg item name, NUL-terminated ascii */
} __attribute__((packed));

struct FWCfgFiles {         /* the entire file directory fw_cfg item */
    uint32_t count;         /* number of entries, in big-endian format */
    struct FWCfgFile f[];   /* array of file entries, see below */
} __attribute__((packed));

extern char g_host_pwd[PATH_MAX];

int host_pwd_init(void);

int cmdline_read_gramine_args(const char* cmdline, int* out_argc, const char** out_argv);
int cmdline_init(char* cmdline, size_t cmdline_size);

int unixtime_init(char* unixtime_s, size_t unixtime_size);
