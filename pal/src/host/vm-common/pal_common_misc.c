/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs for CPU/topology info retrival and low-level hardware operations.
 */

#include "api.h"
#include "cpu.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"

#include "kernel_multicore.h"
#include "kernel_sched.h"

int pal_common_random_bits_read(void* buffer, size_t size) {
    uint32_t rand;
    for (size_t i = 0; i < size; i += sizeof(rand)) {
        rand = rdrand();
        memcpy(buffer + i, &rand, MIN(sizeof(rand), size - i));
    }
    return 0;
}

double pal_common_get_bogomips(void) {
    /* this has to be implemented properly */
    return 4000.0;
}

int pal_common_get_topo_info(struct pal_topo_info* topo_info) {
    /*
     * Hard-coded characteristics: single-node CPU, 3 levels of cache. Number of HW threads/cores is
     * taken from g_num_cpus; CPU cores are represented as non-SMT (no hyper-threads).
     *
     * Note the `static` keyword -- all arrays are allocated in BSS.
     */
    static struct pal_cache_info caches[4] = {
        { .type = CACHE_TYPE_DATA, .level = 1, .size = 32 * 1024,
          .coherency_line_size = 64, .number_of_sets = 64, .physical_line_partition = 1 },
        { .type = CACHE_TYPE_INSTRUCTION, .level = 1, .size = 32 * 1024,
          .coherency_line_size = 64, .number_of_sets = 64, .physical_line_partition = 1 },
        { .type = CACHE_TYPE_UNIFIED, .level = 2, .size = 256 * 1024,
          .coherency_line_size = 64, .number_of_sets = 1024, .physical_line_partition = 1 },
        { .type = CACHE_TYPE_UNIFIED, .level = 3, .size = 12288 * 1024,
          .coherency_line_size = 64, .number_of_sets = 12288, .physical_line_partition = 1 },
    };
    static struct pal_cpu_thread_info threads[MAX_NUM_CPUS] = {
        0 /* to be filled below */
    };
    static struct pal_cpu_core_info cores[MAX_NUM_CPUS] = {
        0 /* to be filled below */
    };
    static struct pal_socket_info sockets[1] = {
        { .unused = 0 },
    };
    static struct pal_numa_node_info numa_nodes[1] = {
        { .is_online = true, .nr_hugepages = {0, 0} },
    };
    static size_t distances[1] = { 10 };

    for (size_t i = 0; i < g_num_cpus; i++) {
        threads[i].is_online = true;
        threads[i].core_id = i;
        threads[i].ids_of_caches[0] = 0;
        threads[i].ids_of_caches[1] = 1;
        threads[i].ids_of_caches[2] = 2;
        threads[i].ids_of_caches[3] = 3;

        cores[i].socket_id = 0;
        cores[i].node_id = 0;
    }

    topo_info->caches = caches;
    topo_info->threads = threads;
    topo_info->cores = cores;
    topo_info->sockets = sockets;
    topo_info->numa_nodes = numa_nodes;
    topo_info->numa_distance_matrix = distances;

    topo_info->caches_cnt = 4;
    topo_info->threads_cnt = g_num_cpus;
    topo_info->cores_cnt = g_num_cpus;
    topo_info->sockets_cnt = 1;
    topo_info->numa_nodes_cnt = 1;
    return 0;
}

int pal_common_segment_base_get(enum pal_segment_reg reg, uintptr_t* addr) {
    switch (reg) {
        case PAL_SEGMENT_FS:
            *addr = rdmsr(MSR_IA32_FS_BASE);
            return 0;
        case PAL_SEGMENT_GS:
            /* GS is internally used, deny any access to it */
            return -PAL_ERROR_DENIED;
        default:
            return -PAL_ERROR_INVAL;
    }
}

int pal_common_segment_base_set(enum pal_segment_reg reg, uintptr_t addr) {
    struct pal_tcb_vm* curr_tcb = (struct pal_tcb_vm*)pal_get_tcb();

    switch (reg) {
        case PAL_SEGMENT_FS:
            curr_tcb->kernel_thread.context.user_fsbase = addr;
            wrmsr(MSR_IA32_FS_BASE, addr);
            return 0;
        case PAL_SEGMENT_GS:
            // The GS segment is used for the internal TCB of PAL
            return -PAL_ERROR_DENIED;
        default:
            return -PAL_ERROR_INVAL;
    }
    return -PAL_ERROR_NOTIMPLEMENTED;
}
