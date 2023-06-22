// Intel Proprietary
//
// Copyright 2021 Intel Corporation All Rights Reserved.
//
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
//
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_mr_verifyreport.c
 * @brief TDGMVERIFYRREPORT API handler
 */

#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "helpers/helpers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_global_data.h"
#include "accessors/ia32_accessors.h"
#include "common/accessors/data_accessors.h"

api_error_type tdg_mr_verifyreport(uint64_t reportmacstruct_gpa)
{
    // Local data and TD's structures
    tdx_module_local_t   *local_data_ptr = get_local_data();
    tdr_t                *tdr_p = local_data_ptr->vp_ctx.tdr;
    tdcs_t               *tdcs_p = local_data_ptr->vp_ctx.tdcs;
    tdvps_t              *tdvps_p = local_data_ptr->vp_ctx.tdvps;

    pa_t                  tdg_reportmacstruct_gpa;
    tdx_module_global_t  *global_data_ptr = get_global_data();
    report_mac_struct_t  *report_mac = NULL;

    uint64_t              seam_status;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdg_reportmacstruct_gpa.raw = reportmacstruct_gpa;

    // Check if the CPU supports local attastation
    if (!global_data_ptr->seamverifyreport_available)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RAX);
    }

    // Verify report GPA is valid
    if (!is_addr_aligned_pwr_of_2(tdg_reportmacstruct_gpa.raw, SIZE_OF_REPORTMAC_STRUCT_IN_BYTES))
    {
        TDX_ERROR("REPORTMACSTRUCT  is gpa (%llx) is not aligned to %d\n",
                   tdg_reportmacstruct_gpa.raw, SIZE_OF_REPORTMAC_STRUCT_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    return_val = check_walk_and_map_guest_side_gpa(tdcs_p,
                                                   tdvps_p,
                                                   tdg_reportmacstruct_gpa,
                                                   tdr_p->key_management_fields.hkid,
                                                   TDX_RANGE_RO,
                                                   PRIVATE_ONLY,
                                                   (void **)&report_mac);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on checking GPA (=%llx) error = %llx\n", tdg_reportmacstruct_gpa.raw, return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RCX);
        goto EXIT;
    }

    seam_status = ia32_seamops_seamverify_report(report_mac);
    switch (seam_status)
    {
    case SEAMOPS_SUCCESS:
        return_val = TDX_SUCCESS;
        break;
    case SEAMOPS_INVALID_CPUSVN:
        return_val = TDX_INVALID_CPUSVN;
        break;
    case SEAMOPS_INVALID_REPORTMACSTRUCT:
        return_val = TDX_INVALID_REPORTMACSTRUCT;
        break;
    default:
        FATAL_ERROR();
        break;
    }

EXIT:
    if (report_mac)
    {
        free_la(report_mac);
    }

    return return_val;
}
