/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Inputs to Gramine from the host: command-line arguments, environment variables, current working
 * dir (PWD), current UNIX time. Inputs are acquired via QEMU's FW CFG interface.
 *
 * Notes on multi-core synchronization:
 *   - All functions are called at init, no sync required
 */

#include <stdint.h>

#include "api.h"
#include "pal_error.h"

#include "kernel_time.h"
#include "kernel_vmm_inputs.h"
#include "vm_callbacks.h"

char g_host_pwd[PATH_MAX];
char g_envs[MAX_ENVS_SIZE];

/* This function copies `input` to a new string (we don't want to modify `input`) and splits the
 * new line in NUL-terminated sub-strings (arguments). Each argument may be enclosed in
 * double-quotes; in this case everything between the double-quotes (including whitespaces) is
 * considered as one argument. Having an argument without a closing double-quote leads to error. No
 * escaping is supported (e.g., `\"` is not allowed). */
static int cmdline_read_common(enum cmdline_parse_type type, const char* input, int* out_cnt,
                               const char** out_array) {
    /* Choose the appropriate starting and ending string as well as the max token size for
     * the specified parse type */
    const char* begin_str;
    const char* end_str;
    size_t max_tokens;
    switch (type) {
        case CMDLINE_ARGS:
            begin_str = GRAMINE_ARGS_BEGIN_STR;
            end_str = GRAMINE_ARGS_END_STR;
            max_tokens = MAX_ARGV_CNT;
            break;
        case CMDLINE_ENVS:
            begin_str = GRAMINE_ENVS_BEGIN_STR;
            end_str = GRAMINE_ENVS_END_STR;
            max_tokens = MAX_ENVS_CNT;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    size_t curr_cnt = 0;

    char* p = strdup(input);
    if (!p)
        return -PAL_ERROR_NOMEM;

    p = strstr(p, begin_str);
    if (!p)
        return -PAL_ERROR_INVAL;

    char* p_end = strstr(p, end_str);
    if (!p_end)
        return -PAL_ERROR_INVAL;

    /* do not count the end_str (e.g. `-gramine-args-end`) and everything after it as arguments */
    *p_end = '\0';

    p += strlen(begin_str);
    while (p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;

        if (curr_cnt == max_tokens)
            return -PAL_ERROR_NOMEM;

        bool token_in_double_quotes = false;
        if (*p == '"') {
            p++;
            token_in_double_quotes = true;
        }

        out_array[curr_cnt] = p;
        curr_cnt++;

        if (token_in_double_quotes) {
            while (*p != '\0' && *p != '"')
                p++;
            if (*p == '\0')
                return -PAL_ERROR_INVAL;
            *p++ = '\0'; /* replace closing double-quote with NUL */
        } else {
            while (*p != '\0' && *p != ' ' && *p != '\t')
                p++;
            *p++ = '\0'; /* replace whitespace with NUL */
        }
    }

    *out_cnt = curr_cnt;
    return 0;
}

/* parse the gramine cmdline args passed by the VMM */
int cmdline_read_gramine_args(const char* cmdline, int* out_argc, const char** out_argv) {
    return cmdline_read_common(CMDLINE_ARGS, cmdline, out_argc, out_argv);
}

/* parse the environment variables passed by the VMM */
int cmdline_read_gramine_envs(const char* envs, int* out_envp_cnt, const char** out_envp) {
    return cmdline_read_common(CMDLINE_ENVS, envs, out_envp_cnt, out_envp);
}

static uint16_t find_fw_cfg_selector(const char* fw_cfg_name) {
	uint32_t fw_cfg_files_count = 0;
    uint8_t* fw_cfg_files_count_raw = (uint8_t*)&fw_cfg_files_count;
    vm_portio_writew(FW_CFG_PORT_SEL, FW_CFG_FILE_DIR);
    for (size_t i = 0; i < sizeof(fw_cfg_files_count); i++)
        fw_cfg_files_count_raw[i] = vm_portio_readb(FW_CFG_PORT_SEL + 1);

    /* QEMU provides in big-endian, but our x86-64 CPU is little-endian */
    fw_cfg_files_count = __builtin_bswap32(fw_cfg_files_count);
    if (fw_cfg_files_count > MAX_FW_CFG_FILES)
        return 0;

    uint16_t fw_cfg_selector = 0;
    for (size_t i = 0; i < fw_cfg_files_count; i++) {
        struct FWCfgFile fw_cfg_file;
        uint8_t* fw_cfg_file_raw = (uint8_t*)&fw_cfg_file;
        for (size_t j = 0; j < sizeof(fw_cfg_file); j++)
            fw_cfg_file_raw[j] = vm_portio_readb(FW_CFG_PORT_SEL + 1);

        if (strlen(fw_cfg_name) + 1 > sizeof(fw_cfg_file.name)) {
            /* make sure the searched-for string is less than the fw_cfg file name limit (56) */
            return 0;
        }

        if (strcmp(fw_cfg_file.name, fw_cfg_name) == 0) {
            fw_cfg_selector = fw_cfg_file.select;
            break;
        }
    }

    return __builtin_bswap16(fw_cfg_selector);
}

int cmdline_init_args(char* cmdline_args, size_t cmdline_args_size) {
    memset(cmdline_args, 0, cmdline_args_size);

    uint16_t fw_cfg_selector = find_fw_cfg_selector("opt/gramine/args");
    if (!fw_cfg_selector)
        return -PAL_ERROR_INVAL;

    vm_portio_writew(FW_CFG_PORT_SEL, fw_cfg_selector);
    for (size_t i = 0; i < cmdline_args_size - 1; i++)
        cmdline_args[i] = vm_portio_readb(FW_CFG_PORT_SEL + 1);

    uint32_t cmdline_args_len = strlen(cmdline_args);
    if (cmdline_args_len == 0 || cmdline_args_len >= PATH_MAX)
        return -PAL_ERROR_INVAL;

    /* note that cmdline is guaranteed to be NULL terminated and have at least one symbol */
    return 0;
}

int cmdline_init_envs(char* cmdline_envs, size_t cmdline_envs_size) {
    memset(cmdline_envs, 0, cmdline_envs_size);

    uint16_t fw_cfg_selector = find_fw_cfg_selector("opt/gramine/envs");
    if (!fw_cfg_selector)
        return -PAL_ERROR_INVAL;

    vm_portio_writew(FW_CFG_PORT_SEL, fw_cfg_selector);
    for (size_t i = 0; i < cmdline_envs_size - 1; i++)
        cmdline_envs[i] = vm_portio_readb(FW_CFG_PORT_SEL + 1);

    uint32_t cmdline_envs_len = strlen(cmdline_envs);
    if (cmdline_envs_len == 0 || cmdline_envs_len >= MAX_ENVS_SIZE)
        return -PAL_ERROR_INVAL;

    /* note that envs is guaranteed to be NULL terminated and have at least one symbol */
    return 0;
}

int host_pwd_init(void) {
    uint16_t fw_cfg_selector = find_fw_cfg_selector("opt/gramine/pwd");
    if (!fw_cfg_selector)
        return -PAL_ERROR_INVAL;

    vm_portio_writew(FW_CFG_PORT_SEL, fw_cfg_selector);
    for (size_t i = 0; i < sizeof(g_host_pwd) - 1; i++)
        g_host_pwd[i] = vm_portio_readb(FW_CFG_PORT_SEL + 1);

    uint32_t len = strlen(g_host_pwd);
    if (len == 0)
        return -PAL_ERROR_INVAL;

    /* note that host PWD is guaranteed to be NULL terminated and have at least one symbol */
    return 0;
}

int unixtime_init(char* unixtime_s, size_t unixtime_size) {
    memset(unixtime_s, 0, unixtime_size);

    uint16_t fw_cfg_selector = find_fw_cfg_selector("opt/gramine/unixtime_s");
    if (!fw_cfg_selector)
        return -PAL_ERROR_INVAL;

    vm_portio_writew(FW_CFG_PORT_SEL, fw_cfg_selector);
    for (size_t i = 0; i < unixtime_size - 1; i++)
        unixtime_s[i] = vm_portio_readb(FW_CFG_PORT_SEL + 1);

    uint32_t len = strlen(unixtime_s);
    if (len == 0 || len >= TIME_S_STR_MAX)
        return -PAL_ERROR_INVAL;

    /* note that `unixtime_s` is guaranteed to be NULL terminated and have at least one symbol */
    return 0;
}
