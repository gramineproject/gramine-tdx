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
    static struct pal_cache_info caches[MAX_NUM_CPUS * MAX_CACHES] = {
        0 /* to be filled below */
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

    size_t caches_cnt = 0;
    /* add one shared L3 */
    caches[caches_cnt].type  = CACHE_TYPE_UNIFIED;
    caches[caches_cnt].level = 3;
    caches[caches_cnt].size  = 12288 * 1024;
    caches[caches_cnt].coherency_line_size     = 64;
    caches[caches_cnt].number_of_sets          = 12288;
    caches[caches_cnt].physical_line_partition = 1;
    caches_cnt++;

    for (size_t i = 0; i < g_num_cpus; i++) {
        threads[i].is_online = true;
        threads[i].core_id = i;

        caches[caches_cnt].type  = CACHE_TYPE_DATA;
        caches[caches_cnt].level = 1;
        caches[caches_cnt].size  = 32 * 1024;
        caches[caches_cnt].coherency_line_size     = 64;
        caches[caches_cnt].number_of_sets          = 64;
        caches[caches_cnt].physical_line_partition = 1;
        threads[i].ids_of_caches[0] = caches_cnt;
        caches_cnt++;

        caches[caches_cnt].type  = CACHE_TYPE_INSTRUCTION;
        caches[caches_cnt].level = 1;
        caches[caches_cnt].size  = 32 * 1024;
        caches[caches_cnt].coherency_line_size     = 64;
        caches[caches_cnt].number_of_sets          = 64;
        caches[caches_cnt].physical_line_partition = 1;
        threads[i].ids_of_caches[1] = caches_cnt;
        caches_cnt++;

        caches[caches_cnt].type  = CACHE_TYPE_UNIFIED;
        caches[caches_cnt].level = 2;
        caches[caches_cnt].size  = 256 * 1024;
        caches[caches_cnt].coherency_line_size     = 64;
        caches[caches_cnt].number_of_sets          = 1024;
        caches[caches_cnt].physical_line_partition = 1;
        threads[i].ids_of_caches[2] = caches_cnt;
        caches_cnt++;

        threads[i].ids_of_caches[3] = /* shared L3 */0;

        cores[i].socket_id = 0;
        cores[i].node_id = 0;
    }

    topo_info->caches = caches;
    topo_info->threads = threads;
    topo_info->cores = cores;
    topo_info->sockets = sockets;
    topo_info->numa_nodes = numa_nodes;
    topo_info->numa_distance_matrix = distances;

    topo_info->caches_cnt = /* per-CPU L1d, L1i, L2 */g_num_cpus * 3 + /* shared L3 */1;
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
