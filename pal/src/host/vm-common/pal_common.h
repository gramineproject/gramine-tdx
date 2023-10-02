/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "cpu.h"
#include "pal.h"

#include "kernel_thread.h"

#define PIPE_BUF_SIZE PRESET_PAGESIZE

struct pal_tcb_vm {
    PAL_TCB common;

    /* private to VM PALs */
    struct {
        struct pal_handle* thread_handle;
        struct thread kernel_thread;
    };
};

extern bool g_use_trusted_files;

extern int g_streams_waiting_events_futex;
extern spinlock_t g_connecting_pipes_lock;
extern LISTP_TYPE(pal_handle) g_server_pipes_list;
extern LISTP_TYPE(pal_handle) g_connecting_pipes_list;

int pal_common_event_create(struct pal_handle** handle_ptr, bool init_signaled, bool auto_clear);
void pal_common_event_set(struct pal_handle* handle);
void pal_common_event_clear(struct pal_handle* handle);
int pal_common_event_wait(struct pal_handle* handle, uint64_t* timeout_us);

int pal_common_streams_wait_events(size_t count, struct pal_handle** handle_array,
                                   pal_wait_flags_t* events, pal_wait_flags_t* ret_events,
                                   uint64_t* timeout_us);

int pal_common_console_open(struct pal_handle** handle, const char* type, const char* uri,
                            enum pal_access access, pal_share_flags_t share,
                            enum pal_create_mode create, pal_stream_options_t options);
int64_t pal_common_console_read(struct pal_handle* handle, uint64_t offset, uint64_t size,
                                void* buffer);
int64_t pal_common_console_write(struct pal_handle* handle, uint64_t offset, uint64_t size,
                                 const void* buffer);
void pal_common_console_destroy(struct pal_handle* handle);
int pal_common_console_flush(struct pal_handle* handle);

int pal_common_file_open(struct pal_handle** handle, const char* type, const char* uri,
                         enum pal_access access, pal_share_flags_t share,
                         enum pal_create_mode create, pal_stream_options_t options);
int64_t pal_common_file_read(struct pal_handle* handle, uint64_t offset, uint64_t count,
                             void* buffer);
int64_t pal_common_file_write(struct pal_handle* handle, uint64_t offset, uint64_t count,
                              const void* buffer);
void pal_common_file_destroy(struct pal_handle* handle);
int pal_common_file_delete(struct pal_handle* handle, enum pal_delete_mode delete_mode);
int pal_common_file_map(struct pal_handle* handle, void* addr, pal_prot_flags_t prot,
                        uint64_t offset, uint64_t size);
int pal_common_file_setlength(struct pal_handle* handle, uint64_t length);
int pal_common_file_flush(struct pal_handle* handle);
int pal_common_file_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* pal_attr);
int pal_common_file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* pal_attr);
int pal_common_file_attrsetbyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr);
int pal_common_file_rename(struct pal_handle* handle, const char* type, const char* uri);

int pal_common_dir_open(struct pal_handle** handle, const char* type, const char* uri,
                        enum pal_access access, pal_share_flags_t share,
                        enum pal_create_mode create, pal_stream_options_t options);
int64_t pal_common_dir_read(struct pal_handle* handle, uint64_t offset, size_t count, void* _buf);
void pal_common_dir_destroy(struct pal_handle* handle);
int pal_common_dir_delete(struct pal_handle* handle, enum pal_delete_mode delete_mode);
int pal_common_dir_rename(struct pal_handle* handle, const char* type, const char* uri);

int pal_common_pipe_open(struct pal_handle** handle, const char* type, const char* uri,
                         enum pal_access access, pal_share_flags_t share,
                         enum pal_create_mode create, pal_stream_options_t options);
int pal_common_pipe_waitforclient(struct pal_handle* server, struct pal_handle** client,
                                  pal_stream_options_t options);
int64_t pal_common_pipe_read(struct pal_handle* handle, uint64_t offset, uint64_t len,
                             void* buffer);
int64_t pal_common_pipe_write(struct pal_handle* handle, uint64_t offset, uint64_t len,
                              const void* buffer);
void pal_common_pipe_destroy(struct pal_handle* handle);
int pal_common_pipe_delete(struct pal_handle* handle, enum pal_delete_mode delete_mode);
int pal_common_pipe_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr);
int pal_common_pipe_attrsetbyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr);

int pal_common_eventfd_open(struct pal_handle** handle, const char* type, const char* uri,
                            enum pal_access access, pal_share_flags_t share,
                            enum pal_create_mode create, pal_stream_options_t options);
int64_t pal_common_eventfd_read(struct pal_handle* handle, uint64_t offset, uint64_t len,
                                void* buffer);
int64_t pal_common_eventfd_write(struct pal_handle* handle, uint64_t offset, uint64_t len,
                                 const void* buffer);
void pal_common_eventfd_destroy(struct pal_handle* handle);
int pal_common_eventfd_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr);

int pal_common_socket_create(enum pal_socket_domain domain, enum pal_socket_type type,
                             pal_stream_options_t options, struct pal_handle** out_handle);

int pal_common_thread_create(struct pal_handle** handle, int (*callback)(void*),
                             const void* param);
noreturn void pal_common_thread_exit(int* clear_child_tid);

int pal_common_random_bits_read(void* buffer, size_t size);
double pal_common_get_bogomips(void);
int pal_common_get_topo_info(struct pal_topo_info* topo_info);
int pal_common_segment_base_get(enum pal_segment_reg reg, uintptr_t* addr);
int pal_common_segment_base_set(enum pal_segment_reg reg, uintptr_t addr);
