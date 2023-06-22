// Intel Proprietary
//
// Copyright 2021 Intel Corporation All Rights Reserved.
//
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
//
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vp_invept.c
 * @brief TDGVPINVVPID API handler
 */
#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "helpers/helpers.h"
#include "data_structures/td_vmcs_init.h"

// Execute INVVPID on the GLA range specified by the GLA list entry
static api_error_type invvpid_gla_list_entry(page_gla_list_entry_t gla_list_entry, uint16_t vpid)
{
    page_gla_list_entry_t  la;
    invvpid_descriptor_t   descriptor;

    descriptor.raw_low = 0;
    descriptor.vpid = vpid;

    la.raw = gla_list_entry.raw;
    la.last_page = 0;

    for (uint32_t i = 0; i <= gla_list_entry.last_page; i++)
    {
        descriptor.la = la.raw;

        if (!ia32_invvpid(&descriptor, INVVPID_INDIVIDUAL_ADDRESS))
        {
            TDX_ERROR("ia32_invvpid failure due to bad LA - 0x%llx\n", la.raw);
            return TDX_GLA_NOT_CANONICAL;
        }

        la.base_gla++;
    }

    return TDX_SUCCESS;
}

typedef union vm_and_flags_u
{
    struct
    {
        uint64_t list           : 1;    // Bit 0 - used for TDG_VP_ENTER input
        uint64_t reserved0      : 51;   // Bits 51:1
        uint64_t vm             : 2;    // Bits 52:53
        uint64_t reserved1      : 10;   // Bits 54:63
    };

    uint64_t raw;
} vm_and_flags_t;
tdx_static_assert(sizeof(vm_and_flags_t) == 8, vm_and_flags_t);

api_error_type tdg_vp_invvpid(uint64_t flags, uint64_t entry_or_list, bool_t* interrupt_occurred)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdr_t*   tdr_p   = tdx_local_data_ptr->vp_ctx.tdr;
    tdcs_t*  tdcs_p  = tdx_local_data_ptr->vp_ctx.tdcs;
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;

    page_gla_list_info_t   gla_list_info;
    page_gla_list_entry_t  gla_list_entry;
    page_gla_list_entry_t* gla_list_p = NULL;
    pa_t                   gla_list_gpa;

    uint16_t               vm_id;
    uint16_t               vpid;
    bool_t                 interrupt_pending = false;
    api_error_type         return_val = TDX_OPERAND_INVALID;

    vm_and_flags_t vm_and_flags = { .raw = flags };

    vm_id = vm_and_flags.vm;
    if ((vm_id == 0) || (vm_id > tdcs_p->management_fields.num_l2_vms)
                     || (vm_and_flags.reserved0 != 0) || (vm_and_flags.reserved1 != 0))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
    }

    vpid = compose_vpid(vm_and_flags.vm, tdr_p->key_management_fields.hkid);
    tdx_debug_assert(vpid != 0);

    if (vm_and_flags.list == 0)
    {
        // Process a single entry
        gla_list_entry.raw = entry_or_list;
        return_val = invvpid_gla_list_entry(gla_list_entry, vpid);
        if (return_val != TDX_SUCCESS)
        {
            goto EXIT;
        }
    }
    else
    {
        // Process a list of entries
        gla_list_info.raw = entry_or_list;
        if (gla_list_info.reserved_0 || gla_list_info.reserved_1 ||
            ((gla_list_info.first_entry + gla_list_info.num_entries) > PAGE_GLA_LIST_MAX_ENTRIES))
        {
            TDX_ERROR("Incorrect GLA list info - 0x%llx\n", gla_list_info.raw);
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        }

        gla_list_gpa.raw = 0;
        gla_list_gpa.page_4k_num = gla_list_info.list_gpa;

        // Verify that GPA is a valid private GPA
        // Translate the GPA; this may result in an EPT violation TD exit or a #VE
        return_val = check_walk_and_map_guest_side_gpa(tdcs_p,
                                                       tdvps_p,
                                                       gla_list_gpa,
                                                       tdr_p->key_management_fields.hkid,
                                                       TDX_RANGE_RO,
                                                       PRIVATE_ONLY,
                                                       (void **)&gla_list_p);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("GLA list GPA is not a valid private GPA - 0x%llx\n", gla_list_gpa.raw);
            return api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        }

        while ((gla_list_info.num_entries > 0) && !interrupt_pending)
        {
            // Process a single entry
            return_val = invvpid_gla_list_entry(gla_list_p[gla_list_info.first_entry], vpid);
            if (return_val != TDX_SUCCESS)
            {
                goto EXIT;
            }

            // Move to the next entry
            gla_list_info.first_entry++;
            gla_list_info.num_entries--;

            // Check for a pending interrupt
            if (is_interrupt_pending_guest_side())
            {
                interrupt_pending = true;
            }
        }

        tdvps_p->guest_state.gpr_state.rdx = gla_list_info.raw;
    }

EXIT:

    *interrupt_occurred = interrupt_pending;

    if (gla_list_p != NULL)
    {
        free_la(gla_list_p);
    }

    return return_val;
}
