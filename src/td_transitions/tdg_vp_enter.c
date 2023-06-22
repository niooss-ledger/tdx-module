// Intel Proprietary
//
// Copyright 2021 Intel Corporation All Rights Reserved.
//
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
//
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vp_enter.c
 * @brief TDGVPENTER API handler
 */
#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "tdx_api_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "helpers/helpers.h"
#include "data_structures/tdx_local_data.h"
#include "memory_handlers/keyhole_manager.h"
#include "td_dispatcher/tdx_td_dispatcher.h"
#include "td_transitions/td_exit.h"
#include "helpers/virt_msr_helpers.h"

static void read_l2_enter_guest_state(tdvps_t* tdvps_ptr, l2_enter_guest_state_t *reg_list_p)
{
    // Read the TDG.VP.ENTER registers list and L2 VMCS
    // Assumes that the active VMCS is the L2 VMCS
    tdx_memcpy(&tdvps_ptr->guest_state.gpr_state, sizeof(tdvps_ptr->guest_state.gpr_state),
               &reg_list_p->gpr_state, sizeof(reg_list_p->gpr_state));

    // Read RSP, RFLAGS, RIP and SSP and VMWRITE to their respective L2 VMCS fields
    ia32_vmwrite(VMX_GUEST_RSP_ENCODE, reg_list_p->gpr_state.rsp);
    ia32_vmwrite(VMX_GUEST_RFLAGS_ENCODE, reg_list_p->rflags);
    ia32_vmwrite(VMX_GUEST_RIP_ENCODE, reg_list_p->rip);
    ia32_vmwrite(VMX_GUEST_SSP_ENCODE, reg_list_p->ssp);
    ia32_vmwrite(VMX_GUEST_INTERRUPT_STATUS_ENCODE, reg_list_p->interrupt_status);
}

typedef union vm_and_flags_u
{
    struct
    {
        uint64_t do_invept      : 1;    // Bit 0 - used for TDG_VP_ENTER input
        uint64_t reserved0      : 51;   // Bits 51:1
        uint64_t vm             : 2;    // Bits 52:53
        uint64_t reserved1      : 10;   // Bits 54:63
    };

    uint64_t raw;
} vm_and_flags_t;
tdx_static_assert(sizeof(vm_and_flags_t) == 8, vm_and_flags_t);

api_error_type tdg_vp_enter(uint64_t flags, uint64_t reg_list_gpa)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdr_t*   tdr_p   = tdx_local_data_ptr->vp_ctx.tdr;
    tdcs_t*  tdcs_p  = tdx_local_data_ptr->vp_ctx.tdcs;
    tdvps_t* tdvps_p = tdx_local_data_ptr->vp_ctx.tdvps;

    uint64_t failed_gpa;
    uint16_t vm_id = 0;
    vm_and_flags_t vm_flags = {.raw = flags};

    guest_interrupt_status_t interrupt_status;
    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };

    // Verify GPA is aligned
    if (!is_addr_aligned_pwr_of_2(reg_list_gpa, 256) ||
        !check_gpa_validity((pa_t)reg_list_gpa, tdcs_p->executions_ctl_fields.gpaw, PRIVATE_ONLY))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
    }

    vm_id = vm_flags.vm;
    if ((vm_id == 0) || (vm_id > tdcs_p->management_fields.num_l2_vms)
                    || (vm_flags.reserved0 != 0) || (vm_flags.reserved1 != 0))
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
    }

    // The L1 VMM must set the L2's virtual APIC page GPA before attempting to run an L2 VCPU
    // Fail on uninitialized virtual APIC page GPA
    if (tdvps_p->management.l2_vapic_gpa[vm_id] == NULL_PA)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_L2_VAPIC_GPA);
    }

    // Check for pending interrupts to L1
    ia32_vmread(VMX_GUEST_INTERRUPT_STATUS_ENCODE, &interrupt_status.raw);
    if ((interrupt_status.rvi & 0xF0UL) > (tdvps_p->vapic.apic[PPR_INDEX] & 0xF0UL))
    {
        return TDX_PENDING_INTERRUPT;
    }

    // If the TD is debuggable, the host VMM can request all L1->L2 entries to be converted to TD exits.
    if (tdvps_p->management.l2_debug_ctls[vm_id].td_exit_on_l1_to_l2)
    {
        tdx_debug_assert(tdcs_p->executions_ctl_fields.attributes.debug == 1);
        async_tdexit_empty_reason(TDX_TD_EXIT_BEFORE_L2_ENTRY);
    }

    /* If any of the GPAs of TDH.VP.ENTER output memory operands is different than the respective GPA
        value stored in TDVPS, set the respective shadow HPA to NULL_PA (-1). */
    if (tdvps_p->management.l2_enter_guest_state_gpa[vm_id] != reg_list_gpa)
    {
        tdvps_p->management.l2_enter_guest_state_gpa[vm_id] = reg_list_gpa;
        tdvps_p->management.l2_enter_guest_state_hpa[vm_id] = NULL_PA;
    }

    set_vm_vmcs_as_active(tdvps_p, vm_id);

    // Translate soft-translated GPAs, if required
    if (!translate_gpas(tdr_p, tdcs_p, tdvps_p, vm_id, &failed_gpa))
    {
        // Translation failed, do an EPT violation TD exit.  Mask off the GPA's lower 12 bits.
        vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;
        async_tdexit_to_vmm(TDX_SUCCESS, vm_exit_reason, 0, 0, failed_gpa & BITS(63,12), 0);
    }

    // ALL CHECKS PASSED:

    tdvps_p->management.curr_vm = vm_id;

    // Before entering the VM, update LP-dependent host state (e.g., RSP)
    update_host_state_in_td_vmcs(tdx_local_data_ptr, tdvps_p, vm_id);

    if (vm_flags.do_invept)
    {
        // Invalidate the L2 VM's GPA translations held by the CPU
        flush_td_asid(tdr_p, tdcs_p, vm_id);
    }

    // Set the VMX preemption timer, if TSC deadline is enabled
    set_vmx_preemption_timer(tdvps_p, vm_id);

    // Map the input memory operands and save for VM exit
    l2_enter_guest_state_t * guest_state_p;
    // Map the pointer with RW access, so that on exit we could use the same cached keyhole
    guest_state_p = (l2_enter_guest_state_t *)map_pa((void*)tdvps_p->management.l2_enter_guest_state_hpa[vm_id], TDX_RANGE_RW);

    // Read the input memory operands
    read_l2_enter_guest_state(tdvps_p, guest_state_p);

    free_la(guest_state_p);

    // Set VMCS.IA32_SPEC_CTRL_SHADOW to the virtual value of IA32_SPEC_CTRL as seen by L2
    ia32_vmwrite(VMX_IA32_SPEC_CTRL_SHADOW,
            calculate_virt_ia32_spec_ctrl(tdcs_p, tdvps_p->guest_msr_state.ia32_spec_ctrl));

    // Restore the guest GPRs and enter the guest TD
    if (tdvps_p->management.vm_launched[vm_id] == true)
    {
        tdx_return_to_td(true, false, &tdvps_p->guest_state.gpr_state);
    }
    else
    {
        tdvps_p->management.vm_launched[vm_id] = true;
        tdx_return_to_td(false, false, &tdvps_p->guest_state.gpr_state);
    }

    // The flow should never reach here.  Any VM entry error is considered fatal
    FATAL_ERROR();

    return TDX_SUCCESS;
}
