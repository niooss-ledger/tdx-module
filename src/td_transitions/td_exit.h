// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_exit.h
 * @brief Everything related to VMM<--->TD transitions
 */


#ifndef SRC_TD_TRANSITIONS_TD_EXIT_H_
#define SRC_TD_TRANSITIONS_TD_EXIT_H_

#include "auto_gen/tdx_error_codes_defs.h"
#include "common/x86_defs/x86_defs.h"
#include "data_structures/tdx_tdvps.h"

#define IA32_DEBUGCTLMSR_BTF                   BIT(1)
#define IA32_DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI BIT(12)
#define IA32_DEBUGCTLMSR_FREEZE_WHILE_SMM      BIT(14)
#define IA32_DEBUGCTLMSR_MASK_BITS_PRESERVED   (IA32_DEBUGCTLMSR_BTF | IA32_DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI | IA32_DEBUGCTLMSR_FREEZE_WHILE_SMM)

#define VMX_GUEST_IA32_PERF_GLOBAL_CONTROL_INIT_VALUE 0x0
#define VMX_GUEST_RTIT_CTL_INIT_VALUE                 0x0
#define VMX_GUEST_LBR_CTL_INIT_VALUE                  0x0
#define VMX_GUEST_DR7_INIT_VALUE                      0x00000400

#define NUM_OF_PRESERVED_KEYHOLES              2

/**
 * @brief Write the TDG.VP.ENTER output operands to memory
 */
void write_l2_enter_outputs(tdvps_t* tdvps_ptr, uint16_t vm_id);

/**
 * @brief Handler routine for asynchronous exit from TD to VMM
 */
void async_tdexit_to_vmm(api_error_code_e tdexit_case,
                         vm_vmexit_exit_reason_t vm_exit_reason,
                         uint64_t exit_qualification,
                         uint64_t extended_exit_qualification,
                         uint64_t gpa,
                         uint64_t vm_exit_interruption_information);

/**
 * @brief Handler routine for cross-TD asynchronous exit
 *
 * @param tdexit_case
 * @param cross_td_status
 * @param target_td
 */
void async_tdexit_cross_td(api_error_code_e tdexit_case,
                           api_error_code_e cross_td_status,
                           pa_t target_td);

/**
 * @brief Handler routine for asynchronous exit from TD to VMM, when there's no exit reason
 *
 * @param tdexit_case
 */
void async_tdexit_empty_reason(api_error_code_e tdexit_case);

/**
 * @brief Converged exit point from TD to VMM, for both async vmexit and vmcall.
 *
 * @param vcpu_state
 * @param last_td_exit
 * @param scrub_mask
 * @param xmm_select
 * @param is_td_dead
 * @param is_trap_exit
 */
void td_vmexit_to_vmm(uint8_t vcpu_state, uint8_t last_td_exit, uint64_t scrub_mask,
                      uint16_t xmm_select, bool_t is_td_dead, bool_t is_trap_exit);

/**
 * @brief Routine for handling exit from L2 VM and reenter to L1 VM
 *
 * @param vm_exit_reason
 * @param vm_exit_qualification
 * @param vm_exit_inter_info
 */
void td_l2_to_l1_exit(vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_qualification_t vm_exit_qualification,
                      vmx_exit_inter_info_t vm_exit_inter_info);

/**
 * @brief Routine for handling exit from L2 VM and reenter to L1 VM
 *
 * @param tdexit_case
 * @param vm_exit_reason
 * @param vm_exit_qualification
 * @param vm_exit_inter_info
 */
void td_l2_to_l1_exit_with_exit_case(api_error_code_e tdexit_case, vm_vmexit_exit_reason_t vm_exit_reason,
                                     vmx_exit_qualification_t vm_exit_qualification,
                                     vmx_exit_inter_info_t vm_exit_inter_info);

#endif /* SRC_TD_TRANSITIONS_TD_EXIT_H_ */
