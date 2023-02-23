/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include "pal.h"
#include "pal_common.h"
#include "pal_internal.h"

int _PalSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                     pal_stream_options_t options, struct pal_handle** out_handle) {
    return pal_common_socket_create(domain, type, options, out_handle);
}

int _PalSocketBind(struct pal_handle* handle, struct pal_socket_addr* addr) {
    if (!handle->sock.ops->bind) {
        return -PAL_ERROR_NOTSUPPORT;
    }

    return handle->sock.ops->bind(handle, addr);
}

int _PalSocketListen(struct pal_handle* handle, unsigned int backlog) {
    if (!handle->sock.ops->listen) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->listen(handle, backlog);
}

int _PalSocketAccept(struct pal_handle* handle, pal_stream_options_t options,
                     struct pal_handle** out_client, struct pal_socket_addr* out_client_addr,
                     struct pal_socket_addr* out_local_addr) {
    if (!handle->sock.ops->accept) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->accept(handle, options, out_client, out_client_addr, out_local_addr);
}

int _PalSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                      struct pal_socket_addr* out_local_addr, bool* out_inprogress) {
    if (!handle->sock.ops->connect) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->connect(handle, addr, out_local_addr, out_inprogress);
}

int _PalSocketSend(struct pal_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (!handle->sock.ops->send) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->send(handle, iov, iov_len, out_size, addr, force_nonblocking);
}

int _PalSocketRecv(struct pal_handle* handle, struct iovec* iov, size_t iov_len,
                   size_t* out_total_size, struct pal_socket_addr* addr, bool force_nonblocking) {
    if (!handle->sock.ops->recv) {
        return -PAL_ERROR_NOTSUPPORT;
    }
    return handle->sock.ops->recv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
}
