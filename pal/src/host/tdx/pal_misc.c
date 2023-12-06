/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * This file contains APIs for miscellaneous use.
 */

#include "api.h"
#include "pal.h"
#include "pal_common.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

#include "kernel_memory.h"
#include "kernel_time.h"
#include "tdx_arch.h"
#include "tdx_quote.h"
#include "vm_callbacks.h"

/* target_info is not used/defined in TDX, but for uniformity with SGX and to satisfy current LibOS
 * assumptions, we always pass dummy target_info string and size */
#define TDX_TARGET_INFO_DUMMY "target_info_dummy"

int _PalRandomBitsRead(void* buffer, size_t size) {
    return pal_common_random_bits_read(buffer, size);
}

int _PalSystemTimeQuery(uint64_t* out_usec) {
    return get_time_in_us(out_usec);
}

int _PalCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[4]) {
    cpuid(leaf, subleaf, values);
    return 0;
}

double _PalGetBogomips(void) {
    return pal_common_get_bogomips();
}

int _PalSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr) {
    return pal_common_segment_base_get(reg, addr);
}

int _PalSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr) {
    return pal_common_segment_base_set(reg, addr);
}

int _PalAttestationReport(const void* user_report_data, size_t* user_report_data_size,
                          void* target_info, size_t* target_info_size, void* report,
                          size_t* report_size) {
    __attribute__((aligned(64))) uint8_t stack_report_data[64];
    __attribute__((aligned(1024))) struct tdx_tdreport_struct stack_report;

    if (!user_report_data_size || !target_info_size || !report_size) {
        /* note that target_info is unused in TDX, but for uniformity with SGX, we require
         * target_info_size pointer to exist */
        return -PAL_ERROR_INVAL;
    }

    if (*user_report_data_size != sizeof(stack_report_data)
            || *target_info_size != sizeof(TDX_TARGET_INFO_DUMMY)
            || *report_size != sizeof(stack_report)) {
        /* inform the caller of TDX sizes for user_report_data, target_info and report */
        goto out;
    }

    if (!user_report_data) {
        /* cannot produce report without user_report_data */
        goto out;
    }

    memcpy(&stack_report_data, user_report_data, sizeof(stack_report_data));

    long tdx_ret;
    do {
        tdx_ret = tdx_tdcall_mr_report((uint64_t)&stack_report, (uint64_t)&stack_report_data);
    } while (tdx_ret >> 32 == TDX_OPERAND_BUSY);

    if (tdx_ret >> 32 != TDX_SUCCESS)
        return (tdx_ret >> 32 == TDX_OPERAND_INVALID) ? -PAL_ERROR_INVAL : -PAL_ERROR_DENIED;

    if (target_info) {
        memcpy(target_info, TDX_TARGET_INFO_DUMMY, sizeof(TDX_TARGET_INFO_DUMMY));
    }

    if (report) {
        /* report may be NULL if caller only wants to know the size of report */
        memcpy(report, &stack_report, sizeof(stack_report));
    }

out:
    *user_report_data_size = sizeof(stack_report_data);
    *target_info_size      = sizeof(TDX_TARGET_INFO_DUMMY);
    *report_size           = sizeof(stack_report);
    return 0;
}

static spinlock_t g_quote_lock = INIT_SPINLOCK_UNLOCKED;
static void* g_shared_mem_for_quote = NULL;
static size_t g_shared_mem_size_for_quote = PAGE_SIZE * 4; /* 16KB is enough for TDX quotes */

int _PalAttestationQuote(const void* user_report_data, size_t user_report_data_size, void* quote,
                         size_t* quote_size) {
    int ret;
    qgs_msg_get_quote_req_t* quote_req   = NULL;
    qgs_msg_get_quote_resp_t* quote_resp = NULL;

    if (!quote_size || user_report_data_size != 64)
        return -PAL_ERROR_INVAL;

    __attribute__((aligned(1024))) struct tdx_tdreport_struct stack_report;

    size_t target_info_size = sizeof(TDX_TARGET_INFO_DUMMY);
    size_t stack_report_size = sizeof(stack_report);
    ret = _PalAttestationReport(user_report_data, &user_report_data_size, /*target_info=*/NULL,
                                &target_info_size, &stack_report, &stack_report_size);
    if (ret < 0)
        return ret;

    /* synchronously waiting for TDX quote to be sent to us using a global lock; this is highly
     * inefficient but we assume that this operation is very rare*/
    spinlock_lock(&g_quote_lock);

    if (!g_shared_mem_for_quote) {
        /* allocate shared memory for TDX quote once and re-use it afterwards */
        g_shared_mem_for_quote = memory_get_shared_region(g_shared_mem_size_for_quote);
        if (!g_shared_mem_for_quote) {
            ret = -PAL_ERROR_NOMEM;
            goto out;
        }
    }

    vm_shared_memset(g_shared_mem_for_quote, 0, g_shared_mem_size_for_quote);

    struct tdx_get_quote_format* tdx_quote = (struct tdx_get_quote_format*)g_shared_mem_for_quote;
    vm_shared_writeq(&tdx_quote->version, 1); /* must be 1 for current TDX */

    size_t quote_req_size = sizeof(qgs_msg_get_quote_req_t) + sizeof(stack_report);
    quote_req = malloc(quote_req_size);
    if (!quote_req) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    quote_req->header.type = GET_QUOTE_REQ;
    quote_req->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    quote_req->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    quote_req->header.size = quote_req_size;
    quote_req->header.error_code = 0;
    quote_req->report_size = sizeof(stack_report);
    quote_req->id_list_size = 0;
    memcpy(quote_req->report_id_list, &stack_report, sizeof(stack_report));

    size_t input_size = TDX_GET_QUOTE_DATA_HEADER_SIZE + quote_req_size;
    vm_shared_writel(&tdx_quote->input_size, input_size);

    /* input data has the format `4B size + qgs_msg_get_quote_req_t object` */
    uint32_t input_size_be = __builtin_bswap32((uint32_t)quote_req_size);
    vm_shared_memcpy((char*)&tdx_quote->data, &input_size_be, TDX_GET_QUOTE_DATA_HEADER_SIZE);
    vm_shared_memcpy((char*)&tdx_quote->data + TDX_GET_QUOTE_DATA_HEADER_SIZE, quote_req,
                     quote_req_size);

    long tdx_ret;
    do {
        tdx_ret = tdx_vmcall_getquote((uint64_t)g_shared_mem_for_quote,
                                       g_shared_mem_size_for_quote);
    } while (tdx_ret == TDG_VP_VMCALL_STATUS_RETRY);

    if (tdx_ret != TDG_VP_VMCALL_STATUS_SUCCESS) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* NOTE: we should ideally wait for a hardware interrupt (previously set up via
     * TDG.VP.VMCALL<SetupEventNotifyInterrupt>), but we just spin for simplicity */
    uint64_t vmm_reports_status;
    do {
        CPU_RELAX();
        vmm_reports_status = vm_shared_readq(&tdx_quote->status_code);
    } while (vmm_reports_status == TDX_GET_QUOTE_STATUS_IN_FLIGHT);

    if (vmm_reports_status != TDX_GET_QUOTE_STATUS_SUCCESS) {
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    size_t output_size = vm_shared_readl(&tdx_quote->output_size);
    if (output_size > g_shared_mem_size_for_quote - offsetof(struct tdx_get_quote_format, data)) {
        /* maliciously large size */
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    /* output data has the format `4B size + qgs_msg_get_quote_resp_t object` */
    size_t quote_resp_size = __builtin_bswap32(vm_shared_readl((uint32_t*)&tdx_quote->data));
    if (quote_resp_size > g_shared_mem_size_for_quote - offsetof(struct tdx_get_quote_format, data)
            - TDX_GET_QUOTE_DATA_HEADER_SIZE) {
        /* maliciously large size */
        ret = -PAL_ERROR_DENIED;
        goto out;
    }
    if (quote_resp_size < sizeof(qgs_msg_get_quote_resp_t)) {
        /* maliciously small size */
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    quote_resp = malloc(quote_resp_size);
    if (!quote_resp) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    vm_shared_memcpy(quote_resp, (char*)&tdx_quote->data + TDX_GET_QUOTE_DATA_HEADER_SIZE,
                     quote_resp_size);

    if (quote_resp->header.major_version != QGS_MSG_LIB_MAJOR_VER ||
            quote_resp->header.type != GET_QUOTE_RESP ||
            quote_resp->header.size != quote_resp_size) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (quote_resp->header.error_code != QGS_MSG_SUCCESS) {
        log_warning("TDX Quote Generation Service (QGS) returned error %d",
                    quote_resp->header.error_code);
        switch (quote_resp->header.error_code) {
            case QGS_MSG_ERROR_OUT_OF_MEMORY:
                ret = -PAL_ERROR_NOMEM;
                goto out;
            case QGS_MSG_ERROR_INVALID_PARAMETER:
            case QGS_MSG_ERROR_INVALID_VERSION:
            case QGS_MSG_ERROR_INVALID_TYPE:
            case QGS_MSG_ERROR_INVALID_SIZE:
            case QGS_MSG_ERROR_INVALID_CODE:
                ret = -PAL_ERROR_INVAL;
                goto out;
            default:
                ret = -PAL_ERROR_DENIED;
                goto out;
        }
    }

    size_t max_id_quote_size = quote_resp_size - sizeof(qgs_msg_get_quote_resp_t);
    if (quote_resp->selected_id_size > max_id_quote_size ||
            quote_resp->quote_size > max_id_quote_size ||
            (quote_resp->selected_id_size + quote_resp->quote_size) > max_id_quote_size) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (*quote_size < quote_resp->quote_size) {
        *quote_size = quote_resp->quote_size;
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    if (quote) {
        /* quote may be NULL if caller only wants to know the size of the quote;
         * note that we ignore ID (if any) */
        memcpy(quote, (char*)&quote_resp->id_quote + quote_resp->selected_id_size,
               quote_resp->quote_size);
    }

    *quote_size = quote_resp->quote_size;
    ret = 0;
out:
    free(quote_req);
    free(quote_resp);
    spinlock_unlock(&g_quote_lock);
    return ret;
}

int _PalGetSpecialKey(const char* name, void* key, size_t* key_size) {
    __UNUSED(name);
    __UNUSED(key);
    __UNUSED(key_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}
