// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_range_block
 * @brief TDHMEMRANGEBLOCK API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"


api_error_type tdh_mem_range_block(page_info_api_input_t sept_level_and_gpa,
                        uint64_t target_tdr_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA and SEPT related variables
    pa_t                  page_gpa;                  // Target page GPA
    ia32e_sept_t        * page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           page_level_entry = LVL_PT; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;  // Indicate SEPT is locked

    // Blocked TD private page variables
    pa_t                  td_page_pa;                    // Physical address of the blocked TD page
    pamt_entry_t        * td_page_pamt_entry_ptr = NULL; // Pointer to the TD PAMT entry

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page (Shared lock!)
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the TD state
    if ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in build state - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    // Verify that GPA mapping input reserved fields equal zero
    if (!is_reserved_zero_in_mappings(sept_level_and_gpa))
    {
        TDX_ERROR("Reserved fields in GPA mappings are not zero\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    page_gpa.raw = 0;
    page_gpa.page_4k_num = sept_level_and_gpa.gpa;
    page_level_entry = sept_level_and_gpa.level;

    // Verify mapping level input is valid
    if (page_level_entry > tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl)
    {
        TDX_ERROR("SEPT EPT page level is not in possible range. Level = %d\n", page_level_entry);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check the page GPA is page aligned
    if (!is_gpa_aligned(sept_level_and_gpa))
    {
        TDX_ERROR("Page GPA is not page (=%llx) aligned\n", TDX_PAGE_SIZE_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_EXCLUSIVE,
                                                      &page_sept_entry_ptr,
                                                      &page_level_entry,
                                                      &page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify the parent entry located for new TD page is not FREE
    if (get_sept_entry_state(&page_sept_entry_copy, page_level_entry) == SEPTE_FREE)
    {
        TDX_ERROR("SEPT entry of GPA is free\n");
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_FREE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify the Secure-EPT entry is not already blocked
    if (page_sept_entry_copy.fields_ps.tdb)
    {
        TDX_ERROR("SEPT entry of GPA is already blocked\n");
        return_val = api_error_with_operand_id(TDX_GPA_RANGE_ALREADY_BLOCKED, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Prepare the EPT entry value with TDB set, RWX cleared and suppress VE set
    ia32e_sept_t epte_val;
    epte_val.raw = page_sept_entry_copy.raw;
    epte_val.fields_ps.tdb = 1;
    epte_val.present.rwx = 0;
    epte_val.fields_4k.supp_ve = 1;

    /*
     * 2MB PENDING leaf entries may have non-0 bits 20:12, used as an init counter by
     * TDG.MEM.PAGE.ACCEPT. In this case they should be cleared.
     * For 2MB Non-PENDING leaf entries, bits 20:12 are already 0 so clearing is harmless.
     **/
    if ((is_ept_leaf_entry(&page_sept_entry_copy, page_level_entry)) && (page_level_entry == LVL_PD))
    {
        epte_val.accept.init_counter = 0;
    }

    // Write the whole 64-bit EPT entry in a single operation
    ia32e_sept_t prev_epte_val = {
                                  .raw = _lock_cmpxchg_64b(page_sept_entry_copy.raw,
                                                           epte_val.raw,
                                                           &page_sept_entry_ptr->raw)
                                 };

    // Check that previous value has the expected value
    if (prev_epte_val.raw != page_sept_entry_copy.raw)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }

    /*---------------------------------------------------------------
        ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    ---------------------------------------------------------------*/

    // Atomically update the PAMT.BEPOCH for the blocked page
    // Read the TD’s epoch (TDCS.TD_EPOCH) and write it to the PAMT entry of the
    // blocked Secure EPT page or TD private page (PAMT.BEPOCH)
    td_page_pa.raw = 0;
    td_page_pa.page_4k_num = page_sept_entry_copy.fields_4k.base;

    if (is_ept_leaf_entry(&page_sept_entry_copy, page_level_entry))
    {
        td_page_pamt_entry_ptr = pamt_implicit_get(td_page_pa, (page_size_t)page_level_entry);
    }
    else
    {
        td_page_pamt_entry_ptr = pamt_implicit_get(td_page_pa, PT_4KB);
    }

    td_page_pamt_entry_ptr->bepoch = tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch;

EXIT:

    // Release all acquired locks
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }
    if (sept_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (td_page_pamt_entry_ptr != NULL)
    {
        free_la(td_page_pamt_entry_ptr);
    }

    return return_val;
}
