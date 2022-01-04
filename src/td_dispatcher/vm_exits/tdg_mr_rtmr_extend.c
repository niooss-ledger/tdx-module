// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_mr_rtmr_extend.c
 * @brief TDGMRRTMREXTEND API handler
 */


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"

#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "tdx_td_api_handlers.h"


api_error_type tdg_mr_rtmr_extend(uint64_t extension_data_gpa, uint64_t index)
{
    api_error_type retval = TDX_OPERAND_INVALID;
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    // Represents 2 SHA384 concatenated (2 * 48 bytes/384 bits)
    uint64_t cat_extended_mr[SIZE_OF_SHA384_HASH_IN_QWORDS*2] = {0};
    uint64_t* second_hash_extended_mr = NULL;
    crypto_api_error sha_error_code;
    uint128_t xmms[16];                  // SSE state backup for crypto

    bool_t rtmr_locked_flag = false;

    // Verify GPA is aligned
    if (!is_addr_aligned_pwr_of_2(extension_data_gpa, 64))
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdr_t* tdr_p = tdx_local_data_ptr->vp_ctx.tdr;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;

    tdx_sanity_check(tdr_p != NULL, SCEC_TDCALL_SOURCE(TDG_MR_RTMR_EXTEND_LEAF), 0);
    tdx_sanity_check(tdcs_p != NULL, SCEC_TDCALL_SOURCE(TDG_MR_RTMR_EXTEND_LEAF), 1);
    tdx_sanity_check(tdvps_p != NULL, SCEC_TDCALL_SOURCE(TDG_MR_RTMR_EXTEND_LEAF), 2);

    // Translation may implicitly mutate into a TD exit or throw a #VE
    // on EPT violation/misconfiguration. Implicitly throws an error if GPA is not specified correctly.
    retval = check_walk_and_map_guest_side_gpa(tdcs_p,
                                               tdvps_p,
                                               (pa_t)extension_data_gpa,
                                               tdr_p->key_management_fields.hkid,
                                               TDX_RANGE_RO,
                                               PRIVATE_ONLY,
                                               /* The second hash in the array will hold this value */
                                               (void**)&second_hash_extended_mr);
    if (retval != TDX_SUCCESS)
    {
        if (retval == TDX_OPERAND_INVALID)
        {
            TDX_ERROR("GPA is not valid = 0x%llx\n", extension_data_gpa);
            retval = api_error_with_operand_id(TDX_OPERAND_INVALID,OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    // Copy the second hash in the extended array
    tdx_memcpy(cat_extended_mr+SIZE_OF_SHA384_HASH_IN_QWORDS,
               SIZE_OF_SHA384_HASH_IN_BYTES,
               second_hash_extended_mr,
               SIZE_OF_SHA384_HASH_IN_BYTES);

    // Return error if register ID is invalid
    if (index >= NUM_RTMRS)
    {
        TDX_ERROR("RTMR index invalid = %llu.\n", index);
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Acquire exclusive access to TDCS.RTMR
    if (acquire_sharex_lock_ex(&tdcs_p->measurement_fields.rtmr_lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Couldn't acquire RTMR lock\n");
        retval = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RTMR);
        goto EXIT;
    }

    rtmr_locked_flag = true;

    // Copy the current rtmr to the first hash in the extended array
    tdx_memcpy(cat_extended_mr,
               SIZE_OF_SHA384_HASH_IN_BYTES*2,
               tdcs_p->measurement_fields.rtmr[index].bytes,
               SIZE_OF_SHA384_HASH_IN_BYTES);

    // Calculate hash from 2 concatenated hashes (current rtmr[i] || new extended value)

    store_xmms_in_buffer(xmms);

    sha_error_code = sha384_generate_hash((const uint8_t*)cat_extended_mr,
                                          SIZE_OF_SHA384_HASH_IN_BYTES*2,
                                          tdcs_p->measurement_fields.rtmr[index].qwords);

    load_xmms_from_buffer(xmms);

    if (sha_error_code != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        FATAL_ERROR();
    }

    retval = TDX_SUCCESS;

EXIT:

    if (rtmr_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_p->measurement_fields.rtmr_lock);
    }
    if(second_hash_extended_mr != NULL)
    {
       free_la(second_hash_extended_mr);
    }


    return retval;
}
