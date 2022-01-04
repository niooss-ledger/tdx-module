// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 *  This File is Automatically generated by the TDX xls extract tool
 *  Spreadsheet Format Version - '1'
 **/

#include "auto_gen/tdvps_fields_lookup.h"


const tdvps_lookup_t tdvps_lookup[MAX_NUM_TDVPS_LOOKUP] = {
 {
   // VCPU_STATE // 0
   .tdvps_field_code =  { .raw  = 0xa000000000000000 }, .offset = 0x100,
   .prod_rd_mask = (0ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // LAUNCHED // 1
   .tdvps_field_code =  { .raw  = 0xa000000000000001 }, .offset = 0x101,
   .prod_rd_mask = (0ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // VCPU_INDEX // 2
   .tdvps_field_code =  { .raw  = 0xa000000000000002 }, .offset = 0x102,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // NUM_TDVPX // 3
   .tdvps_field_code =  { .raw  = 0xa000000000000003 }, .offset = 0x106,
   .prod_rd_mask = (-1ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // TDVPS_PAGE_PA // 4
   .tdvps_field_code =  { .raw  = 0xa000000000000010 }, .offset = 0x108,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // TDVPS_PAGE_PA // 5
   .tdvps_field_code =  { .raw  = 0xa000000000000011 }, .offset = 0x110,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // TDVPS_PAGE_PA // 6
   .tdvps_field_code =  { .raw  = 0xa000000000000012 }, .offset = 0x118,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // TDVPS_PAGE_PA // 7
   .tdvps_field_code =  { .raw  = 0xa000000000000013 }, .offset = 0x120,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // TDVPS_PAGE_PA // 8
   .tdvps_field_code =  { .raw  = 0xa000000000000014 }, .offset = 0x128,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // TDVPS_PAGE_PA // 9
   .tdvps_field_code =  { .raw  = 0xa000000000000015 }, .offset = 0x130,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // ASSOC_LPID // 10
   .tdvps_field_code =  { .raw  = 0xa000000000000004 }, .offset = 0x138,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // ASSOC_HKID // 11
   .tdvps_field_code =  { .raw  = 0xa000000000000005 }, .offset = 0x13c,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // VCPU_EPOCH // 12
   .tdvps_field_code =  { .raw  = 0xa000000000000006 }, .offset = 0x140,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // CPUID_SUPERVISOR_VE // 13
   .tdvps_field_code =  { .raw  = 0xa000000000000007 }, .offset = 0x148,
   .prod_rd_mask = (-1ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // CPUID_USER_VE // 14
   .tdvps_field_code =  { .raw  = 0xa000000000000008 }, .offset = 0x149,
   .prod_rd_mask = (-1ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // IS_SHARED_EPTP_VALID // 15
   .tdvps_field_code =  { .raw  = 0xa000000000000009 }, .offset = 0x14a,
   .prod_rd_mask = (-1ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // LAST_EXIT_TSC // 16
   .tdvps_field_code =  { .raw  = 0xa00000000000000a }, .offset = 0x150,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // PEND_NMI // 17
   .tdvps_field_code =  { .raw  = 0x200000000000000b }, .offset = 0x158,
   .prod_rd_mask = (-1ULL & 0xFFULL), .prod_wr_mask = (-1ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (-1ULL & 0xFFULL)
 },
 {
   // XFAM // 18
   .tdvps_field_code =  { .raw  = 0x200000000000000c }, .offset = 0x160,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST_IDX // 19
   .tdvps_field_code =  { .raw  = 0xa00000000000000d }, .offset = 0x168,
   .prod_rd_mask = (0ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // POSSIBLY_EPF_STEPPING // 20
   .tdvps_field_code =  { .raw  = 0xa00000000000000e }, .offset = 0x169,
   .prod_rd_mask = (0ULL & 0xFFULL), .prod_wr_mask = (0ULL & 0xFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFULL), .dbg_wr_mask = (0ULL & 0xFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 21
   .tdvps_field_code =  { .raw  = 0xa000000000000100 }, .offset = 0x200,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 22
   .tdvps_field_code =  { .raw  = 0xa000000000000101 }, .offset = 0x208,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 23
   .tdvps_field_code =  { .raw  = 0xa000000000000102 }, .offset = 0x210,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 24
   .tdvps_field_code =  { .raw  = 0xa000000000000103 }, .offset = 0x218,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 25
   .tdvps_field_code =  { .raw  = 0xa000000000000104 }, .offset = 0x220,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 26
   .tdvps_field_code =  { .raw  = 0xa000000000000105 }, .offset = 0x228,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 27
   .tdvps_field_code =  { .raw  = 0xa000000000000106 }, .offset = 0x230,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 28
   .tdvps_field_code =  { .raw  = 0xa000000000000107 }, .offset = 0x238,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 29
   .tdvps_field_code =  { .raw  = 0xa000000000000108 }, .offset = 0x240,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 30
   .tdvps_field_code =  { .raw  = 0xa000000000000109 }, .offset = 0x248,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 31
   .tdvps_field_code =  { .raw  = 0xa00000000000010a }, .offset = 0x250,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 32
   .tdvps_field_code =  { .raw  = 0xa00000000000010b }, .offset = 0x258,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 33
   .tdvps_field_code =  { .raw  = 0xa00000000000010c }, .offset = 0x260,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 34
   .tdvps_field_code =  { .raw  = 0xa00000000000010d }, .offset = 0x268,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 35
   .tdvps_field_code =  { .raw  = 0xa00000000000010e }, .offset = 0x270,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 36
   .tdvps_field_code =  { .raw  = 0xa00000000000010f }, .offset = 0x278,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 37
   .tdvps_field_code =  { .raw  = 0xa000000000000110 }, .offset = 0x280,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 38
   .tdvps_field_code =  { .raw  = 0xa000000000000111 }, .offset = 0x288,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 39
   .tdvps_field_code =  { .raw  = 0xa000000000000112 }, .offset = 0x290,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 40
   .tdvps_field_code =  { .raw  = 0xa000000000000113 }, .offset = 0x298,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 41
   .tdvps_field_code =  { .raw  = 0xa000000000000114 }, .offset = 0x2a0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 42
   .tdvps_field_code =  { .raw  = 0xa000000000000115 }, .offset = 0x2a8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 43
   .tdvps_field_code =  { .raw  = 0xa000000000000116 }, .offset = 0x2b0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 44
   .tdvps_field_code =  { .raw  = 0xa000000000000117 }, .offset = 0x2b8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 45
   .tdvps_field_code =  { .raw  = 0xa000000000000118 }, .offset = 0x2c0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 46
   .tdvps_field_code =  { .raw  = 0xa000000000000119 }, .offset = 0x2c8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 47
   .tdvps_field_code =  { .raw  = 0xa00000000000011a }, .offset = 0x2d0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 48
   .tdvps_field_code =  { .raw  = 0xa00000000000011b }, .offset = 0x2d8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 49
   .tdvps_field_code =  { .raw  = 0xa00000000000011c }, .offset = 0x2e0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 50
   .tdvps_field_code =  { .raw  = 0xa00000000000011d }, .offset = 0x2e8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 51
   .tdvps_field_code =  { .raw  = 0xa00000000000011e }, .offset = 0x2f0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // LAST_EPF_GPA_LIST // 52
   .tdvps_field_code =  { .raw  = 0xa00000000000011f }, .offset = 0x2f8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // EXIT_REASON // 53
   .tdvps_field_code =  { .raw  = 0x200000000000000 }, .offset = 0x0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // VALID // 54
   .tdvps_field_code =  { .raw  = 0x200000000000001 }, .offset = 0x4,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // EXIT_QUALIFICATION // 55
   .tdvps_field_code =  { .raw  = 0x200000000000002 }, .offset = 0x8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // GLA // 56
   .tdvps_field_code =  { .raw  = 0x200000000000003 }, .offset = 0x10,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // GPA // 57
   .tdvps_field_code =  { .raw  = 0x200000000000004 }, .offset = 0x18,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // EPTP_INDEX // 58
   .tdvps_field_code =  { .raw  = 0x200000000000005 }, .offset = 0x20,
   .prod_rd_mask = (0ULL & 0xFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFULL)
 },
 {
   // INSTRUCTION_LENGTH // 59
   .tdvps_field_code =  { .raw  = 0x8200000000000010 }, .offset = 0x24,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // INSTRUCTION_INFORMATION // 60
   .tdvps_field_code =  { .raw  = 0x8200000000000011 }, .offset = 0x28,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // RAX // 61
   .tdvps_field_code =  { .raw  = 0x1000000000000000 }, .offset = 0x400,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RCX // 62
   .tdvps_field_code =  { .raw  = 0x1000000000000001 }, .offset = 0x408,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RDX // 63
   .tdvps_field_code =  { .raw  = 0x1000000000000002 }, .offset = 0x410,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RBX // 64
   .tdvps_field_code =  { .raw  = 0x1000000000000003 }, .offset = 0x418,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RSP_PLACEHOLDER // 65
   .tdvps_field_code =  { .raw  = 0x1000000000000004 }, .offset = 0x420,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RBP // 66
   .tdvps_field_code =  { .raw  = 0x1000000000000005 }, .offset = 0x428,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RSI // 67
   .tdvps_field_code =  { .raw  = 0x1000000000000006 }, .offset = 0x430,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // RDI // 68
   .tdvps_field_code =  { .raw  = 0x1000000000000007 }, .offset = 0x438,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R8 // 69
   .tdvps_field_code =  { .raw  = 0x1000000000000008 }, .offset = 0x440,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R9 // 70
   .tdvps_field_code =  { .raw  = 0x1000000000000009 }, .offset = 0x448,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R10 // 71
   .tdvps_field_code =  { .raw  = 0x100000000000000a }, .offset = 0x450,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R11 // 72
   .tdvps_field_code =  { .raw  = 0x100000000000000b }, .offset = 0x458,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R12 // 73
   .tdvps_field_code =  { .raw  = 0x100000000000000c }, .offset = 0x460,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R13 // 74
   .tdvps_field_code =  { .raw  = 0x100000000000000d }, .offset = 0x468,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R14 // 75
   .tdvps_field_code =  { .raw  = 0x100000000000000e }, .offset = 0x470,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // R15 // 76
   .tdvps_field_code =  { .raw  = 0x100000000000000f }, .offset = 0x478,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // DR0 // 77
   .tdvps_field_code =  { .raw  = 0x1100000000000000 }, .offset = 0x480,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // DR1 // 78
   .tdvps_field_code =  { .raw  = 0x1100000000000001 }, .offset = 0x488,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // DR2 // 79
   .tdvps_field_code =  { .raw  = 0x1100000000000002 }, .offset = 0x490,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // DR3 // 80
   .tdvps_field_code =  { .raw  = 0x1100000000000003 }, .offset = 0x498,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // DR6 // 81
   .tdvps_field_code =  { .raw  = 0x1100000000000006 }, .offset = 0x4a0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // XCR0 // 82
   .tdvps_field_code =  { .raw  = 0x1100000000000020 }, .offset = 0x4a8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // CR2 // 83
   .tdvps_field_code =  { .raw  = 0x1100000000000028 }, .offset = 0x4b0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.ENCKEY // 84
   .tdvps_field_code =  { .raw  = 0x1100000000000040 }, .offset = 0x4c0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.ENCKEY // 85
   .tdvps_field_code =  { .raw  = 0x1100000000000041 }, .offset = 0x4c8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.ENCKEY // 86
   .tdvps_field_code =  { .raw  = 0x1100000000000042 }, .offset = 0x4d0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.ENCKEY // 87
   .tdvps_field_code =  { .raw  = 0x1100000000000043 }, .offset = 0x4d8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.INTKEY // 88
   .tdvps_field_code =  { .raw  = 0x1100000000000044 }, .offset = 0x4e0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.INTKEY // 89
   .tdvps_field_code =  { .raw  = 0x1100000000000045 }, .offset = 0x4e8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IWK.FLAGS // 90
   .tdvps_field_code =  { .raw  = 0x1100000000000046 }, .offset = 0x4f0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFULL)
 },
 {
   // VCPU_STATE_DETAILS // 91
   .tdvps_field_code =  { .raw  = 0x9100000000000100 }, .offset = 0x4f8,
   .prod_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_SPEC_CTRL // 92
   .tdvps_field_code =  { .raw  = 0x1300000000000048 }, .offset = 0x500,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_UMWAIT_CONTROL // 93
   .tdvps_field_code =  { .raw  = 0x13000000000000e1 }, .offset = 0x508,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 94
   .tdvps_field_code =  { .raw  = 0x1300000000000186 }, .offset = 0x510,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 95
   .tdvps_field_code =  { .raw  = 0x1300000000000187 }, .offset = 0x518,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 96
   .tdvps_field_code =  { .raw  = 0x1300000000000188 }, .offset = 0x520,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 97
   .tdvps_field_code =  { .raw  = 0x1300000000000189 }, .offset = 0x528,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 98
   .tdvps_field_code =  { .raw  = 0x130000000000018a }, .offset = 0x530,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 99
   .tdvps_field_code =  { .raw  = 0x130000000000018b }, .offset = 0x538,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 100
   .tdvps_field_code =  { .raw  = 0x130000000000018c }, .offset = 0x540,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERFEVTSELx // 101
   .tdvps_field_code =  { .raw  = 0x130000000000018d }, .offset = 0x548,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // MSR_OFFCORE_RSPx // 102
   .tdvps_field_code =  { .raw  = 0x13000000000001a6 }, .offset = 0x550,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // MSR_OFFCORE_RSPx // 103
   .tdvps_field_code =  { .raw  = 0x13000000000001a7 }, .offset = 0x558,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_XFD // 104
   .tdvps_field_code =  { .raw  = 0x13000000000001c4 }, .offset = 0x560,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_XFD_ERR // 105
   .tdvps_field_code =  { .raw  = 0x13000000000001c5 }, .offset = 0x568,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_FIXED_CTRx // 106
   .tdvps_field_code =  { .raw  = 0x1300000000000309 }, .offset = 0x570,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_FIXED_CTRx // 107
   .tdvps_field_code =  { .raw  = 0x130000000000030a }, .offset = 0x578,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_FIXED_CTRx // 108
   .tdvps_field_code =  { .raw  = 0x130000000000030b }, .offset = 0x580,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_FIXED_CTRx // 109
   .tdvps_field_code =  { .raw  = 0x130000000000030c }, .offset = 0x588,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERF_METRICS // 110
   .tdvps_field_code =  { .raw  = 0x1300000000000329 }, .offset = 0x590,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_FIXED_CTR_CTRL // 111
   .tdvps_field_code =  { .raw  = 0x130000000000038d }, .offset = 0x598,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PERF_GLOBAL_STATUS // 112
   .tdvps_field_code =  { .raw  = 0x130000000000038e }, .offset = 0x5a0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_PEBS_ENABLE // 113
   .tdvps_field_code =  { .raw  = 0x13000000000003f1 }, .offset = 0x5a8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // MSR_PEBS_DATA_CFG // 114
   .tdvps_field_code =  { .raw  = 0x13000000000003f2 }, .offset = 0x5b0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // MSR_PEBS_LD_LAT // 115
   .tdvps_field_code =  { .raw  = 0x13000000000003f6 }, .offset = 0x5b8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // MSR_PEBS_FRONTEND // 116
   .tdvps_field_code =  { .raw  = 0x13000000000003f7 }, .offset = 0x5c0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 117
   .tdvps_field_code =  { .raw  = 0x13000000000004c1 }, .offset = 0x5c8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 118
   .tdvps_field_code =  { .raw  = 0x13000000000004c2 }, .offset = 0x5d0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 119
   .tdvps_field_code =  { .raw  = 0x13000000000004c3 }, .offset = 0x5d8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 120
   .tdvps_field_code =  { .raw  = 0x13000000000004c4 }, .offset = 0x5e0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 121
   .tdvps_field_code =  { .raw  = 0x13000000000004c5 }, .offset = 0x5e8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 122
   .tdvps_field_code =  { .raw  = 0x13000000000004c6 }, .offset = 0x5f0,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 123
   .tdvps_field_code =  { .raw  = 0x13000000000004c7 }, .offset = 0x5f8,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_A_PMCx // 124
   .tdvps_field_code =  { .raw  = 0x13000000000004c8 }, .offset = 0x600,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_DS_AREA // 125
   .tdvps_field_code =  { .raw  = 0x1300000000000600 }, .offset = 0x608,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_XSS // 126
   .tdvps_field_code =  { .raw  = 0x1300000000000da0 }, .offset = 0x610,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_LBR_DEPTH // 127
   .tdvps_field_code =  { .raw  = 0x13000000000014cf }, .offset = 0x618,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_STAR // 128
   .tdvps_field_code =  { .raw  = 0x1300000000002081 }, .offset = 0x620,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_LSTAR // 129
   .tdvps_field_code =  { .raw  = 0x1300000000002082 }, .offset = 0x628,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_FMASK // 130
   .tdvps_field_code =  { .raw  = 0x1300000000002084 }, .offset = 0x630,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_KERNEL_GS_BASE // 131
   .tdvps_field_code =  { .raw  = 0x1300000000002102 }, .offset = 0x638,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL)
 },
 {
   // IA32_TSC_AUX // 132
   .tdvps_field_code =  { .raw  = 0x1300000000002103 }, .offset = 0x640,
   .prod_rd_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL), .prod_wr_mask = (0ULL & 0xFFFFFFFFFFFFFFFFULL),
   .dbg_rd_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL), .dbg_wr_mask = (-1ULL & 0xFFFFFFFFFFFFFFFFULL)
 }
};

