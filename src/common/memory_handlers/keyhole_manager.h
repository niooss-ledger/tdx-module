// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file keyhole_manager.h
 * @brief Keyhole manager headers
 */

#ifndef SRC_COMMON_MEMORY_HANDLERS_KEYHOLE_MANAGER_H_
#define SRC_COMMON_MEMORY_HANDLERS_KEYHOLE_MANAGER_H_


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

#define UNDEFINED_IDX                0xFFFF
#define UNDEFINED_IDX_BYTE           0xFF

#define MAX_KEYHOLE_PER_LP          128
#define MAX_STATIC_KEYHOLES         34
#define MAX_CACHEABLE_KEYHOLES      (MAX_KEYHOLE_PER_LP - MAX_STATIC_KEYHOLES)

#define KH_ENTRY_FREE               0
#define KH_ENTRY_MAPPED             1
#define KH_ENTRY_CAN_BE_REMOVED     2

#if MAX_KEYHOLE_PER_LP >= UNDEFINED_IDX
    #error MAX_KEYHOLE_PER_LP is too big
#endif

#define STATIC_KEYHOLE_IDX_TDR            0
#define STATIC_KEYHOLE_IDX_TDCS           (STATIC_KEYHOLE_IDX_TDR + 1)
#define STATIC_KEYHOLE_IDX_TDVPS          (STATIC_KEYHOLE_IDX_TDCS + MAX_MAPPED_TDCS_PAGES)
#define STATIC_KEYHOLE_IDX_OTHERTD_TDCS   (STATIC_KEYHOLE_IDX_TDVPS + MAX_TDVPS_PAGES)

/**
 * @brief Enum for mapping type (Read or Read+Write)
 */
typedef enum
{
    TDX_RANGE_RO   = 0,
    TDX_RANGE_RW   = 1
} mapping_type_t;

/**
 * @brief Initializes the keyhole manager state
 */
void init_keyhole_state(void);

/**
 * @brief Maps a physical page address to a random linear page address. WB memtype is used.
 * @note Do not map more than @c MAX_CACHEABLE_KEYHOLES different pages without freeing them.
 *
 * @param pa Physical address inside the page that needs to be mapped
 * @param mapping_type If write access should be allowed for the linear mapping
 *
 * @return Linear address of the newly mapped page
 */
void* map_pa(void* pa, mapping_type_t mapping_type);

/**
 * @brief Same functionality as map_pa, but maps the PA with UC memtype in the keyhole page table entry
 *
 * @param pa Physical address inside the page that needs to be mapped
 * @param mapping_type If write access should be allowed for the linear mapping
 *
 * @return Linear address of the newly mapped page
 */
void* map_pa_non_wb(void* pa, mapping_type_t mapping_type);

/**
 * @brief Frees a prevously mapped linear address.
 * @note Should be always called if the linear address is no longer needed by the user.
 *
 * @param la linear address of the page that needs to be freed.
 */
void free_la(void* la);

/**
 * @brief Maps a list of physical pages into a continuous linear address space block.
 * @note Maximum allowed amount of pages that can be mapped with that service is @c MAX_STATIC_KEYHOLES.
 *
 * @param pa_array Pointer to 8-bytes array of physical pages addresses that need to be mapped
 * @param array_size Number of entries in the pa_array, can't be bigger than MAX_STATIC_KEYHOLES
 * @param mapping_type If write access should be allowed for the linear mapping
 * @param starting_static_keyhole Choose the starting keyhole out of @c MAX_STATIC_KEYHOLES (starts from 0),
 *                                so that the linear mapping begin from that specific keyhole
 *
 * @return Linear address of the beginning of the mapped block
 */
void* map_continuous_pages(uint64_t* pa_array, uint16_t array_size, mapping_type_t mapping_type,
                           uint16_t starting_static_keyhole);



#endif /* SRC_COMMON_MEMORY_HANDLERS_KEYHOLE_MANAGER_H_ */
