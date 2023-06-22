/**
 * @file tdh_export_pause.c
 * @brief TDH_EXPORT_PAUSE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/op_state_lookup.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"
#include "helpers/migration.h"
//#include "metadata_handlers/metadata_generic.h"

api_error_type tdh_export_pause(uint64_t target_tdr_pa)
{
    // TDR and TDCS
    tdr_t             *tdr_p = NULL;         // Pointer to the owner TDR page
    pa_t               tdr_pa;               // Physical address of the owner TDR page
    pamt_block_t       tdr_pamt_block;       // TDR PAMT block
    pamt_entry_t      *tdr_pamt_entry_ptr = NULL;
    tdcs_t            *tdcs_p = NULL;        // Pointer to the TDCS structure
    bool_t             tdr_locked_flag = false;

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Input register operands
    tdr_pa.raw = target_tdr_pa;

    /*
     * Check, lock and map the owner TDR page.
     * No need to lock the op_state, it is implicitly locked since TDR is exclusively locked
     */
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_p);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    /*
     * Map the TDCS structure and check the state
     * No need to lock the op_state, it is implicitly locked since TDR is exclusively locked
     */
    return_val = check_state_map_tdcs_and_lock(tdr_p, TDX_RANGE_RW, TDX_LOCK_NO_LOCK,
                                               false, TDH_EXPORT_PAUSE_LEAF, &tdcs_p);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("State check or TDCS lock failure - error = %llx\n", return_val);
        goto EXIT;
    }

    /*------------------------------------------------------------------------------------------------
       TDX I/O Placeholder
       -------------------
       Once TDX I/O is added, need to check here that all non-migratable assets have been released.
    ------------------------------------------------------------------------------------------------*/

    /*---------------------------------------------------------------
        ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    ---------------------------------------------------------------*/

    /* Increment the TD’s epoch counter.  As a result, if the export session is aborted,
       the first TDH.VP.ENTER on each VCPU will flush TLB.
       This operation is similar to TDH.MEM.TRACK.  However, we have an exclusive lock on TDR
       so no VCPUs are running, thus REFCOUNT[0] and REFCOUNT[1] are guaranteed to be 0. Also,
       there's no need to lock the epoch.
    */
    if ((tdcs_p->epoch_tracking.epoch_and_refcount.refcount[0] != 0) || (tdcs_p->epoch_tracking.epoch_and_refcount.refcount[1] != 0))
    {
        FATAL_ERROR();
    }
    tdcs_p->epoch_tracking.epoch_and_refcount.td_epoch++;

    // Pause the TD
    tdcs_p->management_fields.op_state = OP_STATE_PAUSED_EXPORT;

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_p);
    }

    if (tdcs_p != NULL)
    {
        free_la(tdcs_p);
    }

    return return_val;
}
