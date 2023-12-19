/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * TCP/UDP sockets, emulated through AF_VSOCK. Notes:
 *   - bound/connected IP addresses are dummy and emulated as localhost,
 *   - UDP sockets are not really supported, they have no send() and recv() callbacks.
 */

#include "api.h"
#include "linux_socket.h"
#include "list.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "socket_utils.h"
#include "spinlock.h"

#include "kernel_sched.h"
#include "kernel_virtio.h"
#include "kernel_virtio_vsock.h"

static struct handle_ops g_tcp_handle_ops;
static struct handle_ops g_udp_handle_ops;
static struct socket_ops g_tcp_sock_ops;
static struct socket_ops g_udp_sock_ops;

/* Default values on a modern Linux kernel. */
static size_t g_default_recv_buf_size = 0x20000;
static size_t g_default_send_buf_size = 0x4000;

/* RX/TX virtqueue events (see virtio-vsock.c) trigger the corresponding futex; we use global
 * futexes instead of per-socket ones for simplicity (it is cumbersome to associate each
 * received/sent network packet to the socket PAL-handle object) and because these events are
 * sufficiently rare and may have sub-optimal performance */
static int g_sockets_reader_futex;
static int g_sockets_writer_futex;

void thread_wakeup_vsock(bool is_read) {
    sched_thread_wakeup(&g_streams_waiting_events_futex);
    sched_thread_wakeup(is_read ? &g_sockets_reader_futex : &g_sockets_writer_futex);
}

static size_t sanitize_size(size_t size) {
    if (size > (1ull << 47)) {
        /* Some random approximation of what is a valid size. */
        return 0;
    }
    return size;
}

/* always returns the localhost address (127.0.0.1 for IPv4 and ::1 for IPv6); note that
 * pal_socket_addr::port is big-endian whereas sockaddr_vm::port is host-byte (little-endian) */
static void vm_to_pal_sockaddr(enum pal_socket_domain domain, const struct sockaddr_vm* vm_addr,
                               struct pal_socket_addr* pal_addr) {
    switch (domain) {
        case PAL_IPV4:;
            pal_addr->domain = PAL_IPV4;
            pal_addr->ipv4.port = htons((uint16_t)vm_addr->svm_port);

            uint8_t ipv4_localhost_addr[4] = {127, 0, 0, 1};
            memcpy(&pal_addr->ipv4.addr, ipv4_localhost_addr, sizeof(pal_addr->ipv4.addr));
            break;
        case PAL_IPV6:;
            pal_addr->domain = PAL_IPV6;
            pal_addr->ipv6.flowinfo = 0;
            pal_addr->ipv6.scope_id = 0;
            pal_addr->ipv6.port = htons((uint16_t)vm_addr->svm_port);

            uint8_t ipv6_localhost_addr[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 1};
            memcpy(pal_addr->ipv6.addr, ipv6_localhost_addr, sizeof(pal_addr->ipv6.addr));
            break;
        case PAL_DISCONNECT:
            pal_addr->domain = PAL_DISCONNECT;
            break;
        default:
            BUG();
    }
}

static void pal_to_vm_sockaddr(const struct pal_socket_addr* pal_addr, struct sockaddr_vm* vm_addr) {
    switch (pal_addr->domain) {
        case PAL_IPV4:;
            vm_addr->svm_family = AF_VSOCK;
            vm_addr->svm_port   = ntohs(pal_addr->ipv4.port);
            break;
        case PAL_IPV6:;
            vm_addr->svm_family = AF_VSOCK;
            vm_addr->svm_port   = ntohs(pal_addr->ipv6.port);
            break;
        case PAL_DISCONNECT:
            log_error("connect(AF_UNSPEC) is not yet implemented!");
            BUG();
        default:
            BUG();
    }
}

static struct pal_handle* create_sock_handle(int fd, enum pal_socket_domain domain,
                                             enum pal_socket_type type,
                                             struct handle_ops* handle_ops, struct socket_ops* ops,
                                             bool is_nonblocking) {
    struct pal_handle* handle = calloc(1, sizeof(*handle));
    if (!handle)
        return NULL;

    handle->hdr.type = PAL_TYPE_SOCKET;
    handle->hdr.ops = handle_ops;
    handle->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    spinlock_init(&handle->sock.lock);
    handle->sock.fd = fd;
    handle->sock.domain = domain;
    handle->sock.type = type;
    handle->sock.ops = ops;
    handle->sock.recv_buf_size = g_default_recv_buf_size;
    handle->sock.send_buf_size = g_default_send_buf_size;
    handle->sock.linger = 0;
    handle->sock.recvtimeout_us = 0;
    handle->sock.sendtimeout_us = 0;
    handle->sock.is_nonblocking = is_nonblocking;
    handle->sock.reuseaddr = false;
    handle->sock.reuseport = false;
    handle->sock.keepalive = false;
    handle->sock.broadcast = false;
    handle->sock.tcp_cork = false;
    handle->sock.tcp_keepidle = DEFAULT_TCP_KEEPIDLE;
    handle->sock.tcp_keepintvl = DEFAULT_TCP_KEEPINTVL;
    handle->sock.tcp_keepcnt = DEFAULT_TCP_KEEPCNT;
    handle->sock.tcp_user_timeout = DEFAULT_TCP_USER_TIMEOUT;
    handle->sock.tcp_nodelay = false;
    handle->sock.ipv6_v6only = false;

    return handle;
}

int pal_common_socket_create(enum pal_socket_domain domain, enum pal_socket_type type,
                             pal_stream_options_t options, struct pal_handle** out_handle) {
    assert(domain == PAL_IPV4 || domain == PAL_IPV6);

    struct handle_ops* handle_ops = NULL;
    struct socket_ops* sock_ops = NULL;
    switch (type) {
        case PAL_SOCKET_TCP:
            handle_ops = &g_tcp_handle_ops;
            sock_ops = &g_tcp_sock_ops;
            break;
        case PAL_SOCKET_UDP:
            handle_ops = &g_udp_handle_ops;
            sock_ops = &g_udp_sock_ops;
            break;
        default:
            BUG();
    }

    int fd = virtio_vsock_socket(AF_VSOCK, VIRTIO_VSOCK_TYPE_STREAM, /*protocol=*/0);
    if (fd < 0)
        return fd;

    struct pal_handle* handle = create_sock_handle(fd, domain, type, handle_ops, sock_ops,
                                                   !!(options & PAL_OPTION_NONBLOCK));
    if (!handle) {
        int ret = virtio_vsock_close(fd, VSOCK_CLOSE_TIMEOUT_US);
        if (ret < 0) {
            log_error("closing socket fd failed: %s", pal_strerror(ret));
        }
        return -PAL_ERROR_NOMEM;
    }

    *out_handle = handle;
    return 0;
}

static void pal_common_socket_destroy(struct pal_handle* handle) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    spinlock_lock(&handle->sock.lock);
    int ret = virtio_vsock_close(handle->sock.fd, VSOCK_CLOSE_TIMEOUT_US);
    spinlock_unlock(&handle->sock.lock);

    if (ret < 0) {
        log_error("closing socket fd failed: %s", pal_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle);
}

static int pal_common_socket_bind(struct pal_handle* handle, struct pal_socket_addr* addr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    if (addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    struct sockaddr_vm addr_vm = { .svm_cid = g_vsock->guest_cid };
    pal_to_vm_sockaddr(addr, &addr_vm);

    uint16_t new_port = 0;
    int ret = virtio_vsock_bind(handle->sock.fd, &addr_vm, sizeof(addr_vm), &new_port,
                                handle->sock.domain == PAL_IPV4, handle->sock.ipv6_v6only,
                                handle->sock.reuseport);
    if (ret < 0)
        return ret;

    switch (addr->domain) {
        case PAL_IPV4:
            if (!addr->ipv4.port) {
                addr->ipv4.port = htons(new_port);
            }
            break;
        case PAL_IPV6:
            if (!addr->ipv6.port) {
                addr->ipv6.port = htons(new_port);
            }
            break;
        default:
            BUG();
    }
    return 0;
}

static int pal_common_tcp_listen(struct pal_handle* handle, unsigned int backlog) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return virtio_vsock_listen(handle->sock.fd, backlog);
}

static int pal_common_tcp_accept(struct pal_handle* handle, pal_stream_options_t options,
                          struct pal_handle** out_client, struct pal_socket_addr* out_client_addr,
                          struct pal_socket_addr* out_local_addr) {
    int ret;
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    spinlock_lock(&handle->sock.lock);

    int client_fd;
    struct sockaddr_vm client_addr_vm = {0};
    size_t client_addr_vm_size = sizeof(client_addr_vm);

    while (true) {
        client_fd = virtio_vsock_accept(handle->sock.fd, &client_addr_vm, &client_addr_vm_size);
        if (client_fd < 0) {
            if (client_fd == -PAL_ERROR_TRYAGAIN && !handle->sock.is_nonblocking) {
                sched_thread_wait(&g_sockets_reader_futex, &handle->sock.lock);
                continue;
            }
            spinlock_unlock(&handle->sock.lock);
            return client_fd;
        }

        /* accept succeeded */
        break;
    }

    spinlock_unlock(&handle->sock.lock); /* done with listening socket here */

    struct pal_handle* client = create_sock_handle(client_fd, handle->sock.domain,
                                                   handle->sock.type, handle->hdr.ops,
                                                   handle->sock.ops,
                                                   !!(options & PAL_OPTION_NONBLOCK));
    if (!client) {
        ret = virtio_vsock_close(client_fd, VSOCK_CLOSE_TIMEOUT_US);
        if (ret < 0) {
            log_error("closing socket fd failed: %s", pal_strerror(ret));
        }
        return -PAL_ERROR_NOMEM;
    }

    struct sockaddr_vm local_addr_vm = {0};
    size_t local_addr_vm_size = sizeof(local_addr_vm);
    ret = virtio_vsock_getsockname(client_fd, &local_addr_vm, &local_addr_vm_size);
    if (ret < 0) {
        _PalObjectDestroy(client);
        return ret;
    }

    if (out_client_addr) {
        vm_to_pal_sockaddr(client->sock.domain, &client_addr_vm, out_client_addr);
    }
    if (out_local_addr) {
        vm_to_pal_sockaddr(client->sock.domain, &local_addr_vm, out_local_addr);
    }

    *out_client = client;
    return 0;
}

static int pal_common_socket_connect(struct pal_handle* handle, struct pal_socket_addr* addr,
                                     struct pal_socket_addr* out_local_addr,
                                     bool* out_inprogress) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    if (addr->domain != PAL_DISCONNECT && addr->domain != handle->sock.domain) {
        return -PAL_ERROR_INVAL;
    }

    struct sockaddr_vm addr_vm = { .svm_cid = g_vsock->host_cid };
    pal_to_vm_sockaddr(addr, &addr_vm);

    int ret = virtio_vsock_connect(handle->sock.fd, &addr_vm, sizeof(addr_vm),
                                   VSOCK_CONNECT_TIMEOUT_US);
    if (ret < 0)
        return ret;

    struct sockaddr_vm local_addr_vm = {0};
    size_t local_addr_vm_size = sizeof(local_addr_vm);
    ret = virtio_vsock_getsockname(handle->sock.fd, &local_addr_vm, &local_addr_vm_size);
    if (ret < 0)
        return ret;

    if (out_local_addr) {
        vm_to_pal_sockaddr(handle->sock.domain, &local_addr_vm, out_local_addr);
    }

    *out_inprogress = false; /* VM PALs do not currently emulate EINPROGRESS */
    return 0;
}

static int pal_common_socket_attrquerybyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    spinlock_lock(&handle->sock.lock);

    memset(attr, 0, sizeof(*attr));

    attr->handle_type = PAL_TYPE_SOCKET;
    attr->nonblocking = handle->sock.is_nonblocking;

    long peeked = virtio_vsock_peek(handle->sock.fd);
    attr->pending_size = peeked >= 0 ? sanitize_size(peeked) : 0;

    attr->socket.linger = handle->sock.linger;
    attr->socket.recv_buf_size = handle->sock.recv_buf_size;
    attr->socket.send_buf_size = handle->sock.send_buf_size;
    attr->socket.receivetimeout_us = handle->sock.recvtimeout_us;
    attr->socket.sendtimeout_us = handle->sock.sendtimeout_us;
    attr->socket.reuseaddr = handle->sock.reuseaddr;
    attr->socket.reuseport = handle->sock.reuseport;
    attr->socket.keepalive = handle->sock.keepalive;
    attr->socket.broadcast = handle->sock.broadcast;
    attr->socket.tcp_cork = handle->sock.tcp_cork;
    attr->socket.tcp_keepidle = handle->sock.tcp_keepidle;
    attr->socket.tcp_keepintvl = handle->sock.tcp_keepintvl;
    attr->socket.tcp_keepcnt = handle->sock.tcp_keepcnt;
    attr->socket.tcp_nodelay = handle->sock.tcp_nodelay;
    attr->socket.tcp_user_timeout = handle->sock.tcp_user_timeout;
    attr->socket.ipv6_v6only = handle->sock.ipv6_v6only;

    spinlock_unlock(&handle->sock.lock);
    return 0;
};

static int pal_common_socket_attrsetbyhdl(struct pal_handle* handle, PAL_STREAM_ATTR* attr) {
    spinlock_lock(&handle->sock.lock);
    handle->sock.is_nonblocking = attr->nonblocking;
    handle->sock.ipv6_v6only    = attr->socket.ipv6_v6only;
    handle->sock.reuseport      = attr->socket.reuseport;

    int ret = virtio_vsock_set_socket_options(handle->sock.fd, handle->sock.ipv6_v6only,
                                              handle->sock.reuseport);

    spinlock_unlock(&handle->sock.lock);
    return ret;
}

static int pal_common_tcp_send(struct pal_handle* handle, struct iovec* iov, size_t iov_len,
                               size_t* out_size, struct pal_socket_addr* addr,
                               bool force_nonblocking) {
    __UNUSED(addr);
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    spinlock_lock(&handle->sock.lock);

    size_t total_bytes = 0;
    size_t iov_idx = 0;
    while (iov_idx < iov_len) {
        if (!iov[iov_idx].iov_base || !iov[iov_idx].iov_len) {
            iov_idx++;
            continue;
        }

        int64_t bytes = virtio_vsock_write(handle->sock.fd, iov[iov_idx].iov_base,
                                           iov[iov_idx].iov_len);
        if (bytes < 0) {
            if (bytes != -PAL_ERROR_TRYAGAIN) {
                /* unrecoverable error, fail immediately */
                spinlock_unlock(&handle->sock.lock);
                return bytes;
            }
            if (total_bytes) {
                /* don't wait/error out if sent something; consider this call successful */
                goto out;
            }
            if (!handle->sock.is_nonblocking && !force_nonblocking) {
                /* blocking socket that didn't send anything must wait */
                sched_thread_wait(&g_sockets_writer_futex, &handle->sock.lock);
                continue;
            }
            /* non-blocking socket that didn't send anything must error out with TRYAGAIN */
            spinlock_unlock(&handle->sock.lock);
            return -PAL_ERROR_TRYAGAIN;
        }

        /* write succeeded, at least partially */
        total_bytes += bytes;

        if ((size_t)bytes < iov[iov_idx].iov_len) {
            /* partial write, let's not try further; should be a rare condition */
            goto out;
        }

        assert((size_t)bytes == iov[iov_idx].iov_len);
        iov_idx++;
    }

out:
    spinlock_unlock(&handle->sock.lock);
    *out_size = total_bytes;
    return 0;
}

static int pal_common_udp_send(struct pal_handle* handle, struct iovec* iov, size_t iov_len,
                               size_t* out_size, struct pal_socket_addr* addr,
                               bool force_nonblocking) {
    __UNUSED(handle);
    __UNUSED(iov);
    __UNUSED(iov_len);
    __UNUSED(out_size);
    __UNUSED(addr);
    __UNUSED(force_nonblocking);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int pal_common_tcp_recv(struct pal_handle* handle, struct iovec* iov, size_t iov_len,
                               size_t* out_total_size, struct pal_socket_addr* addr,
                               bool force_nonblocking) {
    __UNUSED(addr);
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    spinlock_lock(&handle->sock.lock);

    size_t total_bytes = 0;
    size_t iov_idx = 0;
    while (iov_idx < iov_len) {
        if (!iov[iov_idx].iov_base || !iov[iov_idx].iov_len) {
            iov_idx++;
            continue;
        }

        int64_t bytes = virtio_vsock_read(handle->sock.fd, iov[iov_idx].iov_base,
                                          iov[iov_idx].iov_len);
        if (bytes < 0) {
            if (bytes != -PAL_ERROR_TRYAGAIN) {
                /* unrecoverable error, fail immediately */
                spinlock_unlock(&handle->sock.lock);
                return bytes;
            }
            if (total_bytes) {
                /* don't wait/error out if received something; consider this call successful */
                goto out;
            }
            if (!handle->sock.is_nonblocking && !force_nonblocking) {
                /* blocking socket that didn't receive anything must wait */
                sched_thread_wait(&g_sockets_reader_futex, &handle->sock.lock);
                continue;
            }
            /* non-blocking socket that didn't receive anything must error out with TRYAGAIN */
            spinlock_unlock(&handle->sock.lock);
            return -PAL_ERROR_TRYAGAIN;
        }

        /* read succeeded, at least partially */
        total_bytes += bytes;

        if ((size_t)bytes < iov[iov_idx].iov_len) {
            /* partial read, let's not try further; should be a rare condition */
            goto out;
        }

        assert((size_t)bytes == iov[iov_idx].iov_len);
        iov_idx++;
    }

out:
    spinlock_unlock(&handle->sock.lock);
    *out_total_size = total_bytes;
    return 0;
}

static int pal_common_udp_recv(struct pal_handle* handle, struct iovec* iov, size_t iov_len,
                               size_t* out_total_size, struct pal_socket_addr* addr,
                               bool force_nonblocking) {
    __UNUSED(handle);
    __UNUSED(iov);
    __UNUSED(iov_len);
    __UNUSED(out_total_size);
    __UNUSED(addr);
    __UNUSED(force_nonblocking);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int pal_common_tcp_delete(struct pal_handle* handle, enum pal_delete_mode mode) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);

    spinlock_lock(&handle->sock.lock);

    enum virtio_vsock_shutdown shutdown;
    switch (mode) {
        case PAL_DELETE_ALL:
            shutdown = VIRTIO_VSOCK_SHUTDOWN_COMPLETE;
            break;
        case PAL_DELETE_READ:
            shutdown = VIRTIO_VSOCK_SHUTDOWN_RCV;
            break;
        case PAL_DELETE_WRITE:
            shutdown = VIRTIO_VSOCK_SHUTDOWN_SEND;
            break;
        default:
            spinlock_unlock(&handle->sock.lock);
            return -PAL_ERROR_INVAL;
    }

    int ret = virtio_vsock_shutdown(handle->sock.fd, shutdown);

    spinlock_unlock(&handle->sock.lock);
    return ret;
}

static int pal_common_udp_delete(PAL_HANDLE handle, enum pal_delete_mode mode) {
    __UNUSED(handle);
    __UNUSED(mode);
    return 0;
}

static struct socket_ops g_tcp_sock_ops = {
    .bind = pal_common_socket_bind,
    .listen = pal_common_tcp_listen,
    .accept = pal_common_tcp_accept,
    .connect = pal_common_socket_connect,
    .send = pal_common_tcp_send,
    .recv = pal_common_tcp_recv,
};

static struct socket_ops g_udp_sock_ops = {
    .bind = pal_common_socket_bind,
    .connect = pal_common_socket_connect,
    .send = pal_common_udp_send,
    .recv = pal_common_udp_recv,
};

static struct handle_ops g_tcp_handle_ops = {
    .attrquerybyhdl = pal_common_socket_attrquerybyhdl,
    .attrsetbyhdl = pal_common_socket_attrsetbyhdl,
    .delete = pal_common_tcp_delete,
    .destroy = pal_common_socket_destroy,
};

static struct handle_ops g_udp_handle_ops = {
    .attrquerybyhdl = pal_common_socket_attrquerybyhdl,
    .attrsetbyhdl = pal_common_socket_attrsetbyhdl,
    .delete = pal_common_udp_delete,
    .destroy = pal_common_socket_destroy,
};
