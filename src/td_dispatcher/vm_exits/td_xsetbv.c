// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_xsetbv.c
 * @brief VM Exit handler for XSETBV instruction handler
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "helpers/helpers.h"

void td_xsetbv_instruction_exit(void)
{
    // On XSETBV, which attempts to write to XCR0, and on WRMSR of IA32_XSS, the guest TD exits to TDX-SEAM.
    // - If the new value is not natively legal for XCR0 (sets reserved bits,
    //   sets bits for features not supported by the CPU, sets bits for features
    //   not recognized by TDX-SEAM, or uses illegal bit combinations), TDX-SEAM injects a #GP(0) to the guest TD.
    // - Else, if the new value has any bits set which are not allowed by XFAM,
    //   TDX-SEAM injects a #GP(0) to the guest TD.

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvps_t* tdvps_ptr = tdx_local_data_ptr->vp_ctx.tdvps;

    // XCR index must be 0
    if ((uint32_t)tdvps_ptr->guest_state.gpr_state.rcx != 0)
    {
        inject_gp(0);
        return;
    }

    ia32_xcr0_t xcr0;
    xcr0.raw = (tdx_local_data_ptr->td_regs.rdx << 32) | (tdx_local_data_ptr->td_regs.rax & BITS(31,0));

    if (!check_guest_xcr0_value(xcr0, tdx_local_data_ptr->vp_ctx.xfam))
    {
        inject_gp(0);
        return;
    }

    /*-----------------------------------------------------
       All checks passed, emulate the XSETBV instruction
    -----------------------------------------------------*/

    ia32_xsetbv(0, xcr0.raw);
}

