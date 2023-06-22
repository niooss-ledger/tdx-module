/**
 * @file tdh_sys_rd
 * @brief TDH_SYS_RD API handler
 */
#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "memory_handlers/keyhole_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "auto_gen/global_sys_fields_lookup.h"
#include "metadata_handlers/metadata_generic.h"

api_error_type tdg_sys_rd(md_field_id_t field_id)
{
    tdx_module_local_t*     local_data_ptr = get_local_data();
    uint64_t                rd_value = 0;           // Data read from field

    md_access_qualifier_t   access_qual = { .raw = 0 };
    md_context_ptrs_t       md_ctx;
    api_error_type          retval = TDX_SUCCESS;

    // Default output register operands
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx = MD_FIELD_ID_NA;
    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8  = 0;

    // Set the proper context code
    field_id.context_code = MD_CTX_SYS;

    md_ctx.tdr_ptr = NULL;
    md_ctx.tdcs_ptr = NULL;
    md_ctx.tdvps_ptr = NULL;

    if (is_null_field_id(field_id))
    {
        local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx =
                (md_get_next_element_in_context(MD_CTX_SYS, field_id, md_ctx, MD_GUEST_RD, access_qual)).raw;

        retval = TDX_METADATA_FIRST_FIELD_ID_IN_CONTEXT;
        goto EXIT;
    }

    retval = md_check_as_single_element_id(field_id);
    if (retval != TDX_SUCCESS)
    {
        TDX_ERROR("Request field id doesn't match single element = %llx\n", field_id.raw);
        goto EXIT;
    }

    retval = md_read_element(MD_CTX_SYS, field_id, MD_GUEST_RD, access_qual, md_ctx, &rd_value);

    local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.r8 = rd_value;

    if ((retval == TDX_SUCCESS) || is_null_field_id(field_id))
    {
        // Get the next field id if no error or if the current field id in null
        local_data_ptr->vp_ctx.tdvps->guest_state.gpr_state.rdx =
                (md_get_next_element_in_context(MD_CTX_SYS, field_id, md_ctx, MD_GUEST_RD, access_qual)).raw;
    }

EXIT:

    return retval;
}
