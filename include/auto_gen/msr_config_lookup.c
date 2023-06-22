// Intel Proprietary
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided 'as is,' without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 *  This File is Automatically generated by the TDX xls extract tool
 *  Spreadsheet Format Version - '4'
 **/

#include "auto_gen/msr_config_lookup.h"


const msr_lookup_t msr_lookup[MAX_NUM_MSR_LOOKUP] = {

 {
  // 0 - IA32_TIME_STAMP_COUNTER 
  .start_address  = 0x10, .end_address = 0x10, .bit_meaning = MSR_BITMAP_FIXED_01
 },
 {
  // 1 - IA32_SPEC_CTRL 
  .start_address  = 0x48, .end_address = 0x48, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 2 - IA32_PRED_CMD 
  .start_address  = 0x49, .end_address = 0x49, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 3 - IA32_MKTME_PARTITIONING 
  .start_address  = 0x87, .end_address = 0x87, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 4 - IA32_SGXLEPUBKEYHASHx 
  .start_address  = 0x8c, .end_address = 0x8f, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 5 - MSR_WBINVDP 
  .start_address  = 0x98, .end_address = 0x98, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 6 - MSR_WBNOINVDP 
  .start_address  = 0x99, .end_address = 0x99, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 7 - MSR_INTR_PENDING 
  .start_address  = 0x9a, .end_address = 0x9a, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 8 - IA32_SMM_MONITOR_CTL 
  .start_address  = 0x9b, .end_address = 0x9b, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 9 - IA32_SMBASE 
  .start_address  = 0x9e, .end_address = 0x9e, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 10 - IA32_PMCx 
  .start_address  = 0xc1, .end_address = 0xc8, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 11 - IA32_UMWAIT_CONTROL 
  .start_address  = 0xe1, .end_address = 0xe1, .bit_meaning = MSR_BITMAP_OTHER
 },
 {
  // 12 - IA32_ARCH_CAPABILITIES 
  .start_address  = 0x10a, .end_address = 0x10a, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 13 - IA32_FLUSH_CMD 
  .start_address  = 0x10b, .end_address = 0x10b, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 14 - IA32_TSX_CTRL 
  .start_address  = 0x122, .end_address = 0x122, .bit_meaning = MSR_BITMAP_OTHER
 },
 {
  // 15 - IA32_SYSENTER_CS 
  .start_address  = 0x174, .end_address = 0x174, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 16 - IA32_SYSENTER_ESP 
  .start_address  = 0x175, .end_address = 0x175, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 17 - IA32_SYSENTER_EIP 
  .start_address  = 0x176, .end_address = 0x176, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 18 - IA32_PERFEVTSELx 
  .start_address  = 0x186, .end_address = 0x18d, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 19 - IA32_MISC_ENABLE 
  .start_address  = 0x1a0, .end_address = 0x1a0, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 20 - MSR_OFFCORE_RSPx 
  .start_address  = 0x1a6, .end_address = 0x1a7, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 21 - IA32_XFD 
  .start_address  = 0x1c4, .end_address = 0x1c4, .bit_meaning = MSR_BITMAP_OTHER
 },
 {
  // 22 - IA32_XFD_ERR 
  .start_address  = 0x1c5, .end_address = 0x1c5, .bit_meaning = MSR_BITMAP_OTHER
 },
 {
  // 23 - IA32_DEBUGCTL 
  .start_address  = 0x1d9, .end_address = 0x1d9, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 24 - IA32_PLATFORM_DCA_CAP 
  .start_address  = 0x1f8, .end_address = 0x1f8, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 25 - IA32_CPU_DCA_CAP 
  .start_address  = 0x1f9, .end_address = 0x1f9, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 26 - IA32_DCA_0_CAP 
  .start_address  = 0x1fa, .end_address = 0x1fa, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 27 - MSR_SLAM_ENABLE 
  .start_address  = 0x276, .end_address = 0x276, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 28 - IA32_PAT 
  .start_address  = 0x277, .end_address = 0x277, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 29 - IA32_FIXED_CTRx 
  .start_address  = 0x309, .end_address = 0x30c, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 30 - IA32_PERF_METRICS 
  .start_address  = 0x329, .end_address = 0x329, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 31 - IA32_PERF_CAPABILITIES 
  .start_address  = 0x345, .end_address = 0x345, .bit_meaning = MSR_BITMAP_OTHER
 },
 {
  // 32 - IA32_FIXED_CTR_CTRL 
  .start_address  = 0x38d, .end_address = 0x38d, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 33 - IA32_PERF_GLOBAL_STATUS 
  .start_address  = 0x38e, .end_address = 0x38e, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 34 - IA32_PERF_GLOBAL_CTRL 
  .start_address  = 0x38f, .end_address = 0x38f, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 35 - IA32_PERF_GLOBAL_STATUS_RESET 
  .start_address  = 0x390, .end_address = 0x390, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 36 - IA32_PERF_GLOBAL_STATUS_SET 
  .start_address  = 0x391, .end_address = 0x391, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 37 - IA32_PERF_GLOBAL_INUSE 
  .start_address  = 0x392, .end_address = 0x392, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 38 - IA32_PEBS_ENABLE 
  .start_address  = 0x3f1, .end_address = 0x3f1, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 39 - MSR_PEBS_DATA_CFG 
  .start_address  = 0x3f2, .end_address = 0x3f2, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 40 - MSR_PEBS_LD_LAT 
  .start_address  = 0x3f6, .end_address = 0x3f6, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 41 - MSR_PEBS_FRONTEND 
  .start_address  = 0x3f7, .end_address = 0x3f7, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 42 - IA32_VMX_BASIC 
  .start_address  = 0x480, .end_address = 0x480, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 43 - IA32_VMX_PINBASED_CTLS 
  .start_address  = 0x481, .end_address = 0x481, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 44 - IA32_VMX_PROCBASED_CTLS 
  .start_address  = 0x482, .end_address = 0x482, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 45 - IA32_VMX_EXIT_CTLS 
  .start_address  = 0x483, .end_address = 0x483, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 46 - IA32_VMX_ENTRY_CTLS 
  .start_address  = 0x484, .end_address = 0x484, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 47 - IA32_VMX_MISC 
  .start_address  = 0x485, .end_address = 0x485, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 48 - IA32_VMX_CR0_FIXED0 
  .start_address  = 0x486, .end_address = 0x486, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 49 - IA32_VMX_CR0_FIXED1 
  .start_address  = 0x487, .end_address = 0x487, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 50 - IA32_VMX_CR4_FIXED0 
  .start_address  = 0x488, .end_address = 0x488, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 51 - IA32_VMX_CR4_FIXED1 
  .start_address  = 0x489, .end_address = 0x489, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 52 - IA32_VMX_VMCS_ENUM 
  .start_address  = 0x48a, .end_address = 0x48a, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 53 - IA32_VMX_PROCBASED_CTLS2 
  .start_address  = 0x48b, .end_address = 0x48b, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 54 - IA32_VMX_EPT_VPID_CAP 
  .start_address  = 0x48c, .end_address = 0x48c, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 55 - IA32_VMX_TRUE_PINBASED_CTLS 
  .start_address  = 0x48d, .end_address = 0x48d, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 56 - IA32_VMX_TRUE_PROCBASED_CTLS 
  .start_address  = 0x48e, .end_address = 0x48e, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 57 - IA32_VMX_TRUE_EXIT_CTLS 
  .start_address  = 0x48f, .end_address = 0x48f, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 58 - IA32_VMX_TRUE_ENTRY_CTLS 
  .start_address  = 0x490, .end_address = 0x490, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 59 - IA32_VMX_VMFUNC 
  .start_address  = 0x491, .end_address = 0x491, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 60 - IA32_VMX_PROCBASED_CTLS3 
  .start_address  = 0x492, .end_address = 0x492, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 61 - IA32_A_PMCx 
  .start_address  = 0x4c1, .end_address = 0x4c8, .bit_meaning = MSR_BITMAP_PERFMON
 },
 {
  // 62 - IA32_SGX_SVN_STATUS 
  .start_address  = 0x500, .end_address = 0x500, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 63 - IA32_RTIT_OUTPUT_BASE 
  .start_address  = 0x560, .end_address = 0x560, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 64 - IA32_RTIT_OUTPUT_MASK_PTRS 
  .start_address  = 0x561, .end_address = 0x561, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 65 - IA32_RTIT_CTL 
  .start_address  = 0x570, .end_address = 0x570, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 66 - IA32_RTIT_STATUS 
  .start_address  = 0x571, .end_address = 0x571, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 67 - IA32_RTIT_CR3_MATCH 
  .start_address  = 0x572, .end_address = 0x572, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 68 - IA32_RTIT_ADDR0_A 
  .start_address  = 0x580, .end_address = 0x580, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 69 - IA32_RTIT_ADDR0_B 
  .start_address  = 0x581, .end_address = 0x581, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 70 - IA32_RTIT_ADDR1_A 
  .start_address  = 0x582, .end_address = 0x582, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 71 - IA32_RTIT_ADDR1_B 
  .start_address  = 0x583, .end_address = 0x583, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 72 - IA32_RTIT_ADDR2_A 
  .start_address  = 0x584, .end_address = 0x584, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 73 - IA32_RTIT_ADDR2_B 
  .start_address  = 0x585, .end_address = 0x585, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 74 - IA32_RTIT_ADDR3_A 
  .start_address  = 0x586, .end_address = 0x586, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 75 - IA32_RTIT_ADDR3_B 
  .start_address  = 0x587, .end_address = 0x587, .bit_meaning = MSR_BITMAP_XFAM_PT
 },
 {
  // 76 - IA32_DS_AREA 
  .start_address  = 0x600, .end_address = 0x600, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 77 - IA32_U_CET 
  .start_address  = 0x6a0, .end_address = 0x6a0, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 78 - IA32_S_CET 
  .start_address  = 0x6a2, .end_address = 0x6a2, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 79 - IA32_PL0_SSP 
  .start_address  = 0x6a4, .end_address = 0x6a4, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 80 - IA32_PL1_SSP 
  .start_address  = 0x6a5, .end_address = 0x6a5, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 81 - IA32_PL2_SSP 
  .start_address  = 0x6a6, .end_address = 0x6a6, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 82 - IA32_PL3_SSP 
  .start_address  = 0x6a7, .end_address = 0x6a7, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 83 - IA32_INTERRUPT_SSP_TABLE_ADDR 
  .start_address  = 0x6a8, .end_address = 0x6a8, .bit_meaning = MSR_BITMAP_XFAM_CET
 },
 {
  // 84 - IA32_TSC_DEADLINE 
  .start_address  = 0x6e0, .end_address = 0x6e0, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 85 - IA32_PKRS 
  .start_address  = 0x6e1, .end_address = 0x6e1, .bit_meaning = MSR_BITMAP_OTHER
 },
 {
  // 86 - Reserved for xAPIC MSRs 
  .start_address  = 0x800, .end_address = 0x801, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 87 - Reserved for xAPIC MSRs 
  .start_address  = 0x804, .end_address = 0x807, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 88 - IA32_X2APIC_TPR 
  .start_address  = 0x808, .end_address = 0x808, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 89 - Reserved for xAPIC MSRs 
  .start_address  = 0x809, .end_address = 0x809, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 90 - IA32_X2APIC_PPR 
  .start_address  = 0x80a, .end_address = 0x80a, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 91 - IA32_X2APIC_EOI 
  .start_address  = 0x80b, .end_address = 0x80b, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 92 - Reserved for xAPIC MSRs 
  .start_address  = 0x80c, .end_address = 0x80c, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 93 - Reserved for xAPIC MSRs 
  .start_address  = 0x80e, .end_address = 0x80e, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 94 - IA32_X2APIC_ISRx 
  .start_address  = 0x810, .end_address = 0x817, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 95 - IA32_X2APIC_TMRx 
  .start_address  = 0x818, .end_address = 0x81f, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 96 - IA32_X2APIC_IRRx 
  .start_address  = 0x820, .end_address = 0x827, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 97 - Reserved for xAPIC MSRs 
  .start_address  = 0x829, .end_address = 0x82e, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 98 - Reserved for xAPIC MSRs 
  .start_address  = 0x831, .end_address = 0x831, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 99 - IA32_X2APIC_SELF_IPI 
  .start_address  = 0x83f, .end_address = 0x83f, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 100 - Reserved for xAPIC MSRs 
  .start_address  = 0x840, .end_address = 0x87f, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 101 - Reserved for xAPIC MSRs 
  .start_address  = 0x880, .end_address = 0x8bf, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 102 - Reserved for xAPIC MSRs 
  .start_address  = 0x8c0, .end_address = 0x8ff, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 103 - IA32_TME_CAPABILITY 
  .start_address  = 0x981, .end_address = 0x981, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 104 - IA32_TME_ACTIVATE 
  .start_address  = 0x982, .end_address = 0x982, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 105 - IA32_TME_EXCLUDE_MASK 
  .start_address  = 0x983, .end_address = 0x983, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 106 - IA32_TME_EXCLUDE_BASE 
  .start_address  = 0x984, .end_address = 0x984, .bit_meaning = MSR_BITMAP_FIXED_1_OTHER
 },
 {
  // 107 - IA32_UINTR_RR 
  .start_address  = 0x985, .end_address = 0x985, .bit_meaning = MSR_BITMAP_XFAM_ULI
 },
 {
  // 108 - IA32_UINTR_HANDLER 
  .start_address  = 0x986, .end_address = 0x986, .bit_meaning = MSR_BITMAP_XFAM_ULI
 },
 {
  // 109 - IA32_UINTR_STACKADJUST 
  .start_address  = 0x987, .end_address = 0x987, .bit_meaning = MSR_BITMAP_XFAM_ULI
 },
 {
  // 110 - IA32_UINTR_MISC 
  .start_address  = 0x988, .end_address = 0x988, .bit_meaning = MSR_BITMAP_XFAM_ULI
 },
 {
  // 111 - IA32_UINTR_PD 
  .start_address  = 0x989, .end_address = 0x989, .bit_meaning = MSR_BITMAP_XFAM_ULI
 },
 {
  // 112 - IA32_UINTR_TT 
  .start_address  = 0x98a, .end_address = 0x98a, .bit_meaning = MSR_BITMAP_XFAM_ULI
 },
 {
  // 113 - IA32_DEBUG_INTERFACE 
  .start_address  = 0xc80, .end_address = 0xc80, .bit_meaning = MSR_BITMAP_FIXED_01
 },
 {
  // 114 - IA32_BNDCFGS 
  .start_address  = 0xd90, .end_address = 0xd90, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 115 - IA32_PASID 
  .start_address  = 0xd93, .end_address = 0xd93, .bit_meaning = MSR_BITMAP_FIXED_1_GP_AT_EXIT
 },
 {
  // 116 - IA32_XSS 
  .start_address  = 0xda0, .end_address = 0xda0, .bit_meaning = MSR_BITMAP_FIXED_01
 },
 {
  // 117 - IA32_LBR_INFO 
  .start_address  = 0x1200, .end_address = 0x12ff, .bit_meaning = MSR_BITMAP_XFAM_LBR
 },
 {
  // 118 - IA32_LBR_CTL 
  .start_address  = 0x14ce, .end_address = 0x14ce, .bit_meaning = MSR_BITMAP_XFAM_LBR
 },
 {
  // 119 - IA32_LBR_DEPTH 
  .start_address  = 0x14cf, .end_address = 0x14cf, .bit_meaning = MSR_BITMAP_XFAM_LBR
 },
 {
  // 120 - IA32_LBR_FROM_IP 
  .start_address  = 0x1500, .end_address = 0x15ff, .bit_meaning = MSR_BITMAP_XFAM_LBR
 },
 {
  // 121 - IA32_LBR_TO_IP 
  .start_address  = 0x1600, .end_address = 0x16ff, .bit_meaning = MSR_BITMAP_XFAM_LBR
 },
 {
  // 122 - IA32_EFER 
  .start_address  = 0xc0000080, .end_address = 0xc0000080, .bit_meaning = MSR_BITMAP_FIXED_01
 },
 {
  // 123 - IA32_STAR 
  .start_address  = 0xc0000081, .end_address = 0xc0000081, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 124 - IA32_LSTAR 
  .start_address  = 0xc0000082, .end_address = 0xc0000082, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 125 - IA32_FMASK 
  .start_address  = 0xc0000084, .end_address = 0xc0000084, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 126 - IA32_FSBASE 
  .start_address  = 0xc0000100, .end_address = 0xc0000100, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 127 - IA32_GSBASE 
  .start_address  = 0xc0000101, .end_address = 0xc0000101, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 128 - IA32_KERNEL_GS_BASE 
  .start_address  = 0xc0000102, .end_address = 0xc0000102, .bit_meaning = MSR_BITMAP_FIXED_00
 },
 {
  // 129 - IA32_TSC_AUX 
  .start_address  = 0xc0000103, .end_address = 0xc0000103, .bit_meaning = MSR_BITMAP_FIXED_00
 }
};

