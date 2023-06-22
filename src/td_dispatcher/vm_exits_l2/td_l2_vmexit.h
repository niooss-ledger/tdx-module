// Intel Proprietary
//
// Copyright 2021 Intel Corporation All Rights Reserved.
//
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
//
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_l2_vmexit.h
 * @brief Everything related to handling of L2 VMEXIT's and VT-related flows
 */

#ifndef SRC_TD_DISPATCHER_VM_EXITS_L2_TD_L2_VMEXIT_H_
#define SRC_TD_DISPATCHER_VM_EXITS_L2_TD_L2_VMEXIT_H_


typedef enum l2_exit_route_e
{
    L2_EXIT_ROUTE_TD_EXIT,
    L2_EXIT_ROUTE_RESUME_L2,
    L2_EXIT_ROUTE_L2_TO_L1_EXIT
} l2_exit_route_t;

/**
 * @brief Handler for interrupt exit from L2 TD
 *
 * @return Required routing, whether TD exit, resuming L2, or emulating L2 to L1 exit
 */
l2_exit_route_t td_l2_interrupt_exit(tdx_module_local_t* tdx_local_data_ptr,
                                     vmx_exit_inter_info_t vm_exit_inter_info, uint16_t vm_id);

/**
 * @brief Handler for exception or NMI exit from L2 TD
 */
void td_l2_exception_or_nmi_exit(vm_vmexit_exit_reason_t vm_exit_reason,
                                 vmx_exit_qualification_t vm_exit_qualification,
                                 vmx_exit_inter_info_t vm_exit_inter_info);

/**
 * @brief Handler for CR access from L2 TD
 */
cr_write_status_e td_l2_cr_access_exit(vmx_exit_qualification_t vm_exit_qualification, uint16_t vm_id);

/**
 * @brief Handler for EPT violations occurred in L2 TD
 */
void td_l2_ept_violation_exit(vm_vmexit_exit_reason_t vm_exit_reason, vmx_exit_qualification_t exit_qualification);


#endif /* SRC_TD_DISPATCHER_VM_EXITS_L2_TD_L2_VMEXIT_H_ */
