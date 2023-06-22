/**
 * @file metadata_td.h
 * @brief TD-context (TDR and TDCS) metadata handler
 */

#ifndef SRC_COMMON_METADATA_HANDLERS_METADATA_TD_H_
#define SRC_COMMON_METADATA_HANDLERS_METADATA_TD_H_

#include "metadata_generic.h"
#include "auto_gen/tdr_tdcs_fields_lookup.h"
#include "helpers/error_reporting.h"

api_error_code_e md_td_read_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t* out_rd_value);

api_error_code_e md_td_read_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD]);

api_error_code_e md_td_write_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t wr_value, uint64_t wr_request_mask,
        uint64_t* old_value);

api_error_code_e md_td_write_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD], uint64_t wr_mask);

/**
 * @brief Private helper function to get the L2 VM index
 * Assumes that the current CLASS_CODE is one of the L2 class codes - no sanity checks are done
 *
 * @return VM index:  0 if n/a
 */

#define L2_TD_CLASS_CODE_INC 4   // Increment of CLASS_CODE per VM

_STATIC_INLINE_ uint16_t md_td_get_l2_vm_index(uint16_t class_code)
{
    tdx_debug_assert(class_code >= MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE);

    return ((class_code - MD_TDCS_L2_SECURE_EPT_ROOT__1_CLASS_CODE) / L2_TD_CLASS_CODE_INC) + 1;
};


#endif /* SRC_COMMON_METADATA_HANDLERS_METADATA_TD_H_ */
