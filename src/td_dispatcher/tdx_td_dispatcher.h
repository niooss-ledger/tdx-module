// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_td_dispatcher.h
 * @brief VM Exit from TD entry point and API dispatcher
 */
#ifndef __TDX_TD_DISPATCHER_H_INCLUDED__
#define __TDX_TD_DISPATCHER_H_INCLUDED__


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_tdvps.h"


/**
 * @brief Entry point to TDX module from TD generated by a VM Exit
 *
 * @note Written in assembly and defined as the HOST_RIP in the TD VMCS
 *
 * @return None
 */
__attribute__((visibility("hidden"))) void tdx_tdexit_entry_point(void);

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
void tdx_failed_vmentry(void);
#endif


/**
 * @brief Dispatcher for TD side VM Exits
 *
 * @note
 *
 * @return None
 */
void tdx_td_dispatcher(void);


/**
 * @brief Restores TDVPS registers state to local data and call the exit point to return to TD
 *
 * @note
 *
 * @return None
 */
void tdx_return_to_td(bool_t launch_state);

/**
 * @brief If we got here and BUS_LOCK_PREEMPTED is still set, it means that a bus lock preemption
 * has been indicated on VM exit (bit 26 of the exit reason) but the VM exit handler decided
 * not to do a TD exit.
 * In this case, we do an asynchronous TD exit here with a synthetic BUS_LOCK (74) exit reason.
 *
 * @note
 *
 * @return None
 */
void bus_lock_exit ( void );

/**
 * @brief Check if VM exit handler injected an HW exception into the TD.
 *        If the TD is debuggable and execption bitmap bit v is set, then TD Exit with a
          synthetic EXCEPTION_OR_NMI exit reason.
 *
 * @note
 *
 * @return None
 */
void check_hw_exception( void );

/**
 * @brief Exit point returning to TD from TDX module
 *
 * @note Written in assembly
 *
 * @return None
 */
__attribute__((visibility("hidden"))) void tdx_tdentry_to_td(bool_t launch_state, tdvps_guest_state_t* guest_state_ptr);



#endif // __TDX_TD_DISPATCHER_H_INCLUDED__
