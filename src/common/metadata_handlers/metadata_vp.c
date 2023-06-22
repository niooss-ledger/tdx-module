/**
 * @file metadata_vp.c
 * @brief VP-context (TDVPS and TD-VMCS) metadata handler
 */

#include "metadata_generic.h"
#include "metadata_vp.h"
#include "auto_gen/tdvps_fields_lookup.h"
#include "auto_gen/td_vmcs_fields_lookup.h"
#include "helpers/error_reporting.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "data_structures/tdx_tdvps.h"
#include "helpers/helpers.h"
#include "helpers/virt_msr_helpers.h"

#define POSTED_INTER_DESCRIPTOR_SIZE  64

_STATIC_INLINE_ bool_t is_initial_invalid_pa(uint64_t pa)
{
    return ((pa & BIT(63)) != 0);
}

static bool_t calculate_native_tsc(uint64_t virtual_tsc, uint64_t tsc_multiplier, uint64_t tsc_offset, uint64_t* native_tsc)
{
    // Virtual TSC to Native TSC Conversion

    // virtual_tsc = ((native_tsc * tsc_multiplier) >> 48) + tsc_offset

    // 1. tmp64b = virtual_tsc - tsc_offset
    // 2. tmp128b.low_64b = tmp64b << 48
    // 3. tmp128b.high_64b = tmp64b >> 16

    uint128_t tmp_128b;

    tmp_128b.qwords[0] = (virtual_tsc - tsc_offset) << 48;
    tmp_128b.qwords[1] = (virtual_tsc - tsc_offset) >> 16;

    // 4. if (tmp128b.high_64b >= tsc_multiplier) error  // Division would result in an overflow
    if (tmp_128b.qwords[1] >= tsc_multiplier)    // Division would result in an overflow
    {
        return false;
    }

    // 5. native_tsc = tmp_128b / tsc_multiplier;
    _ASM_VOLATILE_ (
        "divq %3\n"
        : "=a"(*native_tsc)
        : "a"(tmp_128b.qwords[0]), "d"(tmp_128b.qwords[1]), "r"(tsc_multiplier)
        : );

    return true;
}

static bool_t check_and_update_ia32_dbgctrl(uint64_t* wr_value, tdcs_t* tdcs_ptr)
{
    ia32_debugctl_t ia32_debugctl;
    ia32_debugctl.raw = *wr_value;

    // For simplicity, we check  on TDHSYSINIT/TDHSYSINITLP that all non-reserved
    // bits are supported.  Thus, checking of unsupported bits is done by the
    // write mask and there's no need for an explicit check here.*/

    // Bits 7:6 must not be set to 01 unless the TD is in debug mode
    if ((ia32_debugctl.bts == 0) &&
        (ia32_debugctl.tr == 1) &&
        (tdcs_ptr->executions_ctl_fields.attributes.debug == 0))
    {
        return false;
    }

    // Update TD VMCS with the input value, except bit 13
    ia32_debugctl.en_uncore_pmi = get_local_data()->ia32_debugctl_value.en_uncore_pmi;
    *wr_value = ia32_debugctl.raw;

    return true;
}

static void combine_l2_cr0_cr4_controls(uint64_t base_l2_guest_host_mask, uint64_t base_l2_read_shadow,
                                        uint64_t l2_guest_host_mask_by_l1, uint64_t l2_read_shadow_by_l1,
                                        uint64_t* combined_l2_guest_host_mask, uint64_t* combined_l2_read_shadow)
{
    // If bit X value in either l2_guest_host_mask_by_l1 or td_guest_host_mask is 1, bit X is host-owned (1)
    *combined_l2_guest_host_mask = base_l2_guest_host_mask | l2_guest_host_mask_by_l1;

    // If bit X value in l2_guest_host_mask_by_l1 is 1, bit X is owned by the L1 VMM.
    // In this case, return bit X of l2_read_shadow_by_l1.
    // Else, If bit X value in base_l2_guest_host_mask is 1, bit X is owned by the TDX module.
    // In this case, return bit X of base_l2_read_shadow.
    // Else, return 0.

    // Bits owned by the L1 VMM are not owned by the TDX module
    base_l2_guest_host_mask &= ~l2_guest_host_mask_by_l1;

    *combined_l2_read_shadow = (base_l2_guest_host_mask & base_l2_read_shadow) |
                               (l2_guest_host_mask_by_l1 & l2_read_shadow_by_l1);
}

static void combine_and_write_l2_cr0_controls(tdvps_t* tdvps_ptr, uint16_t vm_id)
{
    uint64_t combined_l2_guest_host_mask, combined_l2_read_shadow;

    combine_l2_cr0_cr4_controls(tdvps_ptr->management.base_l2_cr0_guest_host_mask,
                                tdvps_ptr->management.base_l2_cr0_read_shadow,
                                tdvps_ptr->management.shadow_cr0_guest_host_mask[vm_id],
                                tdvps_ptr->management.shadow_cr0_read_shadow[vm_id],
                                &combined_l2_guest_host_mask, &combined_l2_read_shadow);

    ia32_vmwrite(VMX_CR0_GUEST_HOST_MASK_ENCODE, combined_l2_guest_host_mask);
    ia32_vmwrite(VMX_CR0_READ_SHADOW_ENCODE, combined_l2_read_shadow);
}

static void combine_and_write_l2_cr4_controls(tdvps_t* tdvps_ptr, uint16_t vm_id)
{
    uint64_t combined_l2_guest_host_mask, combined_l2_read_shadow;

    combine_l2_cr0_cr4_controls(tdvps_ptr->management.base_l2_cr4_guest_host_mask,
                                tdvps_ptr->management.base_l2_cr4_read_shadow,
                                tdvps_ptr->management.shadow_cr4_guest_host_mask[vm_id],
                                tdvps_ptr->management.shadow_cr4_read_shadow[vm_id],
                                &combined_l2_guest_host_mask, &combined_l2_read_shadow);

    ia32_vmwrite(VMX_CR4_GUEST_HOST_MASK_ENCODE, combined_l2_guest_host_mask);
    ia32_vmwrite(VMX_CR4_READ_SHADOW_ENCODE, combined_l2_read_shadow);
}

// Apply the CR controls to get the CR virtual value
_STATIC_INLINE_ uint64_t apply_cr0_cr4_controls_for_read(uint64_t cr, uint64_t guest_host_mask, uint64_t read_shadow)
{
    return (cr & ~guest_host_mask) | (read_shadow & guest_host_mask);
}

// Apply the CR controls to write the CR virtual value
_STATIC_INLINE_ bool_t apply_cr0_cr4_controls_for_write(uint64_t old_cr, uint64_t* new_cr,
                                                        uint64_t guest_host_mask, uint64_t read_shadow)
{
    // Check that no host-owned (visible by the guest as the shadow) bits are modified
    if ((*new_cr & guest_host_mask) != (read_shadow & guest_host_mask))
    {
        return false;
    }

    // Modify only guest-owned bits; keep host-owned bits
    *new_cr = (old_cr & guest_host_mask) | (*new_cr & ~guest_host_mask);

    return true;
}


static bool_t check_l2_procbased_exec_ctls(const tdcs_t* tdcs_p, vmx_procbased_ctls_t old_ctls,
                                           vmx_procbased_ctls_t new_ctls)
{
    tdx_module_global_t* global_data = get_global_data();

    // This field's writable bits is not static.  In addition to the write mask that was
    // applied by the caller, we need to check compatibility with the value read on TDH_SYS_INIT from
    // the IA32_VMX_PROCBASED_CTLS2 MSR.
    if ((~new_ctls.raw & global_data->plt_common_config.ia32_vmx_true_procbased_ctls.not_allowed0) |
        (new_ctls.raw & ~global_data->plt_common_config.ia32_vmx_true_procbased_ctls.allowed1))
    {
        return false;
    }

    // RDPMC_EXITING is writable only if the value of the TD's ATTRIBUTES.PERFMON is 1
    if ((new_ctls.rdpmc_exiting != old_ctls.rdpmc_exiting) && !tdcs_p->executions_ctl_fields.attributes.perfmon)
    {
        return false;
    }

    return true;
}

static bool_t check_l2_procbased_exec_ctls2(const tdcs_t* tdcs_p, vmx_procbased_ctls2_t old_ctls2,
                                            vmx_procbased_ctls2_t new_ctls2)
{
    tdx_module_global_t* global_data = get_global_data();

    // This field's writable bits is not static.  In addition to the write mask that was
    // applied above, we need to check compatibility with the value read on TDH_SYS_INIT from
    // the IA32_VMX_PROCBASED_CTLS2 MSR.
    if ((~new_ctls2.raw & global_data->plt_common_config.ia32_vmx_procbased_ctls2.not_allowed0) |
        (new_ctls2.raw & ~global_data->plt_common_config.ia32_vmx_procbased_ctls2.allowed1))
    {
        return false;
    }

    // enable_user_level_wait_and_pause is writable only if the value of the
    // TD's virtualized CPUID(0x7,0x0).ECX[5] (WAITPKG) is 1
    if ((new_ctls2.en_guest_wait_pause != old_ctls2.en_guest_wait_pause) &&
        !tdcs_p->executions_ctl_fields.cpuid_flags.waitpkg_supported)
    {
        return false;
    }

    // enable_pconfig is writable only if the value of the
    // TD's virtualized CPUID(0x7,0x0).EDX[18] (PCONFIG) is 1
    if ((new_ctls2.en_pconfig != old_ctls2.en_pconfig) &&
        !tdcs_p->executions_ctl_fields.cpuid_flags.mktme_supported)
    {
        return false;
    }

    return true;
}

static bool_t check_l1_procbased_exec_ctls2(const tdcs_t* tdcs_p, vmx_procbased_ctls2_t new_ctls2)
{
    tdx_module_global_t* global_data = get_global_data();

    // This field's writable bits is not static.  In addition to the write mask that was
    // applied above, we need to check compatibility with the value read on TDH_SYS_INIT from
    // the IA32_VMX_PROCBASED_CTLS2 MSR.
    if ((~new_ctls2.raw & global_data->plt_common_config.ia32_vmx_procbased_ctls2.not_allowed0) |
        (new_ctls2.raw & ~global_data->plt_common_config.ia32_vmx_procbased_ctls2.allowed1))
    {
        return false;
    }

    // For PML to be enabled, the TD must be debuggable
    // PML address must have been set (as a valid shared HPA) for PML to be enabled
    if (new_ctls2.en_pml)
    {
        uint64_t pml_address;
        ia32_vmread(VMX_PML_LOG_ADDRESS_FULL_ENCODE, &pml_address);
        if (!tdcs_p->executions_ctl_fields.attributes.debug || is_initial_invalid_pa(pml_address))
        {
            return false;
        }
    }

    return true;
}

static uint32_t get_msr_index_from_shadow_msr_bitmap_field_id(md_field_id_t field_id)
{
    uint32_t index;

    // For MSR bitmaps, the field code is the offset (in 8 bytes units) in the MSR bitmaps page.
    index = field_id.field_code * 64;
    // Isolate index in the read exit bitmaps (lower two bitmaps)
    index &= (2 * MSR_RANGE_SIZE) - 1;
    if (index >= MSR_RANGE_SIZE)
    {
        // 2nd read and 2nd write bitmaps are for the high range
        index = index - MSR_RANGE_SIZE + HIGH_MSR_START;
    }

    return index;
}

static uint64_t md_vp_get_element_special_rd_handle(md_field_id_t field_id, md_access_t access_type,
                                                    md_context_ptrs_t md_ctx, uint16_t vm_id, uint64_t read_value)
{
    //----------------------------------
    //     Handle Special Read Cases
    //----------------------------------
    if (field_id.class_code == MD_TDVPS_VMCS_CLASS_CODE)
    {
        switch (field_id.field_code)
        {
            case VMX_GUEST_CR0_ENCODE:
            {
                /* For export and import, read the CR0 value as if read by the guest.
                   For debug, read the native CR0 value.
                */
                if ((access_type == MD_EXPORT_MUTABLE) || (access_type == MD_IMPORT_MUTABLE))
                {
                    uint64_t guest_host_mask, rd_shadow;
                    ia32_vmread(VMX_CR0_GUEST_HOST_MASK_ENCODE, &guest_host_mask);
                    ia32_vmread(VMX_CR0_READ_SHADOW_ENCODE, &rd_shadow);

                    read_value = apply_cr0_cr4_controls_for_read(read_value, guest_host_mask, rd_shadow);
                }

                break;
            }
            case VMX_GUEST_CR4_ENCODE:
            {
                /* For export, read the CR4 value as if read by the guest.
                For debug, read the native CR4 value.
                */
                if ((access_type == MD_EXPORT_MUTABLE) || (access_type == MD_IMPORT_MUTABLE))
                {
                    uint64_t guest_host_mask, rd_shadow;
                    ia32_vmread(VMX_CR4_GUEST_HOST_MASK_ENCODE, &guest_host_mask);
                    ia32_vmread(VMX_CR4_READ_SHADOW_ENCODE, &rd_shadow);

                    read_value = apply_cr0_cr4_controls_for_read(read_value, guest_host_mask, rd_shadow);
                }

                break;
            }
            default:
                tdx_debug_assert(0);
                break;
        }
    }
    else if ((field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE) ||
             (field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE) ||
             (field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE))
    {
        switch (field_id.field_code)
        {
            case VMX_CR0_GUEST_HOST_MASK_ENCODE:
            {
                if ((access_type != MD_HOST_RD) && (access_type != MD_HOST_WR))
                {
                    // On L1 VMM read and on export, read the value from the shadow
                    tdx_debug_assert((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) ||
                                     (access_type == MD_EXPORT_IMMUTABLE));
                    read_value = md_ctx.tdvps_ptr->management.shadow_cr0_guest_host_mask[vm_id];
                }
                break;
            }
            case VMX_CR0_READ_SHADOW_ENCODE:
            {
                if ((access_type != MD_HOST_RD) && (access_type != MD_HOST_WR))
                {
                    // On L1 VMM read and on export, read the value from the shadow
                    tdx_debug_assert((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) ||
                                     (access_type == MD_EXPORT_IMMUTABLE));
                    read_value = md_ctx.tdvps_ptr->management.shadow_cr0_read_shadow[vm_id];
                }
                break;
            }
            case VMX_CR4_GUEST_HOST_MASK_ENCODE:
            {
                if ((access_type != MD_HOST_RD) && (access_type != MD_HOST_WR))
                {
                    // On L1 VMM read and on export, read the value from the shadow
                    tdx_debug_assert((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) ||
                                     (access_type == MD_EXPORT_IMMUTABLE));
                    read_value = md_ctx.tdvps_ptr->management.shadow_cr4_guest_host_mask[vm_id];
                }
                break;
            }
            case VMX_CR4_READ_SHADOW_ENCODE:
            {
                if ((access_type != MD_HOST_RD) && (access_type != MD_HOST_WR))
                {
                    // On L1 VMM read and on export, read the value from the shadow
                    tdx_debug_assert((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) ||
                                     (access_type == MD_EXPORT_IMMUTABLE));
                    read_value = md_ctx.tdvps_ptr->management.shadow_cr4_read_shadow[vm_id];
                }
                break;
            }
            case VMX_GUEST_CR0_ENCODE:
            {
                if ((access_type != MD_HOST_RD) && (access_type != MD_HOST_WR))
                {
                    tdx_debug_assert((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) ||
                                     (access_type == MD_EXPORT_IMMUTABLE));
                    read_value = apply_cr0_cr4_controls_for_read(read_value,
                            md_ctx.tdvps_ptr->management.base_l2_cr0_guest_host_mask,
                            md_ctx.tdvps_ptr->management.base_l2_cr0_read_shadow);
                }
                break;
            }
            case VMX_GUEST_CR4_ENCODE:
            {
                if ((access_type != MD_HOST_RD) && (access_type != MD_HOST_WR))
                {
                    tdx_debug_assert((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) ||
                                     (access_type == MD_EXPORT_IMMUTABLE));
                    read_value = apply_cr0_cr4_controls_for_read(read_value,
                            md_ctx.tdvps_ptr->management.base_l2_cr4_guest_host_mask,
                            md_ctx.tdvps_ptr->management.base_l2_cr4_read_shadow);
                }
                break;
            }
#ifdef L1_VM_DOS_POLICY_SUPPORT
            case VMX_NOTIFY_WINDOW_ENCODE:
            {
                // Read the shadow value
                read_value = md_ctx.tdvps_ptr->management.shadow_notify_window[vm_id];
                break;
            }
#endif
            case VMX_PAUSE_LOOP_EXITING_GAP_ENCODE:
            {
                if ((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) || (access_type == MD_EXPORT_IMMUTABLE))
                {
                    read_value = md_ctx.tdvps_ptr->management.shadow_ple_gap[vm_id];
                }
                // In other case the value is being read directly from the VMCS by VMREAD
                // before the special read handling
                break;
            }
            case VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE:
            {
                if ((access_type == MD_GUEST_RD) || (access_type == MD_GUEST_WR) || (access_type == MD_EXPORT_IMMUTABLE))
                {
                    read_value = md_ctx.tdvps_ptr->management.shadow_ple_window[vm_id];
                }
                // In other case the value is being read directly from the VMCS by VMREAD
                // before the special read handling
                break;
            }
            case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
            {
                // Read the shadow value
                read_value = md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[vm_id];
                break;
            }
            case VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE:
            {
                // Read the shadow value;
                // The VMCS may hold another value if L2_CTLS[vm].ENABLE_SHARED_EPTP is false.
                read_value = md_ctx.tdvps_ptr->management.shadow_shared_eptp[vm_id];
                break;
            }
            case VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE:
            {
                // Read the shadow GPA value
                read_value = md_ctx.tdvps_ptr->management.l2_vapic_gpa[vm_id];
                break;
            }
#ifdef L2_VE_SUPPORT
            case VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE:
            {
                // Read the shadow GPA value
                read_value = md_ctx.tdvps_ptr->management.ve_info_gpa[vm_id];
                break;
            }
#endif
            default:
                tdx_debug_assert(0);
                break;
        }
    }
    else if (field_id.class_code == MD_TDVPS_GUEST_STATE_CLASS_CODE)
    {
        switch (field_id.field_code)
        {
            case MD_TDVPS_VCPU_STATE_DETAILS_FIELD_CODE:
            {
                // Calculate virtual interrupt pending status
                vcpu_state_t vcpu_state_details;
                guest_interrupt_status_t interrupt_status;
                uint64_t interrupt_status_raw;

                set_vm_vmcs_as_active(md_ctx.tdvps_ptr, 0);

                ia32_vmread(VMX_GUEST_INTERRUPT_STATUS_ENCODE, &interrupt_status_raw);
                interrupt_status.raw = (uint16_t)interrupt_status_raw;
                vcpu_state_details.raw = 0ULL;
                if ((interrupt_status.rvi & 0xF0UL) > (md_ctx.tdvps_ptr->vapic.apic[PPR_INDEX] & 0xF0UL))
                {
                    vcpu_state_details.vmxip = 1ULL;
                }
                read_value = vcpu_state_details.raw;

                break;
            }
            default:
                break;
        }
    }
    else if (field_id.class_code == MD_TDVPS_GUEST_MSR_STATE_CLASS_CODE)
    {
        switch (field_id.field_code)
        {
            case MD_TDVPS_IA32_SPEC_CTRL_FIELD_CODE:
            {
                // Return the value of IA32_SPEC_CTRL as seen by the guest TD
                read_value = calculate_virt_ia32_spec_ctrl(md_ctx.tdcs_ptr, md_ctx.tdvps_ptr->guest_msr_state.ia32_spec_ctrl);
                break;
            }
            default:
                break;
        }
    }

    return read_value;
}

static uint64_t* calc_elem_ptr(md_field_id_t field_id, const md_lookup_t* entry, md_context_ptrs_t md_ctx)
{
    tdx_debug_assert(md_ctx.tdvps_ptr != NULL);
    tdx_debug_assert(entry->field_id.inc_size == 0);

    uint64_t elem_size = BIT(entry->field_id.element_size_code);
    uint64_t elem_num = field_id.field_code - entry->field_id.field_code;
    uint64_t offset = entry->offset + (elem_num * elem_size);
    return (uint64_t*)((uint8_t*)md_ctx.tdvps_ptr + offset);
}

static api_error_code_e md_vp_get_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
        uint64_t* out_rd_mask, uint64_t* out_wr_mask, uint64_t* out_rd_value, uint64_t** out_elem_ptr)
{
    uint64_t rd_mask = 0, wr_mask = 0;
    uint64_t read_value;
    uint16_t vm_id = 0;

    md_get_rd_wr_mask(entry, access_type, access_qual, &rd_mask, &wr_mask);

    switch (field_id.class_code)
    {
        case MD_TDVPS_VMCS_CLASS_CODE:
        case MD_TDVPS_VMCS_1_CLASS_CODE:
        case MD_TDVPS_VMCS_2_CLASS_CODE:
        case MD_TDVPS_VMCS_3_CLASS_CODE:
        {
            if (field_id.class_code != MD_TDVPS_VMCS_CLASS_CODE)
            {
                vm_id = md_vp_get_l2_vm_index(field_id.class_code);
                if(vm_id > md_ctx.tdcs_ptr->management_fields.num_l2_vms)
                {
                    return TDX_METADATA_FIELD_ID_INCORRECT;
                }
            }

            vmcs_field_code_t vmcs_field_code;
            vmcs_field_code.raw = field_id.field_code;
            // We do not allow using the "High" access type
            if (vmcs_field_code.access_type == VMCS_FIELD_ACCESS_TYPE_HIGH)
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            set_vm_vmcs_as_active(md_ctx.tdvps_ptr, vm_id);

            // Read the VMCS field. VMREAD may return an error if the field code does not match
            // a real VMCS field.
            if (!ia32_try_vmread(vmcs_field_code.raw, &read_value))
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            *out_elem_ptr = NULL; // No element address on VMCS elements
            break;
        }
        case MD_TDVPS_MSR_BITMAPS_1_CLASS_CODE:
        case MD_TDVPS_MSR_BITMAPS_2_CLASS_CODE:
        case MD_TDVPS_MSR_BITMAPS_3_CLASS_CODE:
        {
            vm_id = (uint16_t)md_vp_get_l2_vm_index(field_id.class_code);
            if(vm_id > md_ctx.tdcs_ptr->management_fields.num_l2_vms)
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            tdx_debug_assert(md_ctx.tdvps_ptr != NULL);
            uint64_t elem_num = field_id.field_code - entry->field_id.field_code;

            if ((access_type == MD_HOST_RD) || (access_type == MD_HOST_WR))
            {
                // On host access (only for debug), return the real MSR bitmaps value
                *out_elem_ptr = &md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_msr_bitmaps[elem_num];
                read_value = md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_msr_bitmaps[elem_num];
            }
            else
            {
                // On guest access and for migration, return the shadow MSR bitmaps value
                *out_elem_ptr = &md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_shadow_msr_bitmaps[elem_num];
                read_value = md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_shadow_msr_bitmaps[elem_num];
            }

            break;
        }
        case MD_TDVPS_MSR_BITMAPS_SHADOW_1_CLASS_CODE:
        case MD_TDVPS_MSR_BITMAPS_SHADOW_2_CLASS_CODE:
        case MD_TDVPS_MSR_BITMAPS_SHADOW_3_CLASS_CODE:

            vm_id = (uint16_t)md_vp_get_l2_vm_index(field_id.class_code);
            if(vm_id > md_ctx.tdcs_ptr->management_fields.num_l2_vms)
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            // Fallthrough - no break;
        case MD_TDVPS_VAPIC_CLASS_CODE:
        case MD_TDVPS_GUEST_GPR_STATE_CLASS_CODE:
        case MD_TDVPS_GUEST_EXT_STATE_CLASS_CODE:
        case MD_TDVPS_GUEST_MSR_STATE_CLASS_CODE:
        case MD_TDVPS_GUEST_STATE_CLASS_CODE:
        case MD_TDVPS_VE_INFO_CLASS_CODE:
        case MD_TDVPS_MANAGEMENT_CLASS_CODE:
        case MD_TDVPS_CPUID_CONTROL_CLASS_CODE:
        case MD_TDVPS_EPT_VIOLATION_LOG_CLASS_CODE:
        {
            uint64_t* elem_ptr = calc_elem_ptr(field_id, entry, md_ctx);

            *out_elem_ptr = elem_ptr;
            read_value = *elem_ptr;

            break;
        }
        default:
            FATAL_ERROR();
            break;
    }

    if (entry->special_rd_handling)
    {
        read_value = md_vp_get_element_special_rd_handle(field_id, access_type, md_ctx, vm_id, read_value);
    }

    *out_rd_mask = rd_mask;
    *out_wr_mask = wr_mask;
    *out_rd_value = read_value & md_get_element_size_mask(entry->field_id.element_size_code);

    return TDX_SUCCESS;
}

api_error_code_e md_vp_read_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t* out_rd_value)
{
    uint64_t rd_mask, wr_mask, read_value;
    uint64_t* elem_ptr;
    api_error_code_e status;

    status = md_vp_get_element(field_id, entry, access_type, access_qual, md_ctx, &rd_mask, &wr_mask,
                               &read_value, &elem_ptr);

    if (status != TDX_SUCCESS)
    {
        return status;
    }

    if (rd_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_READABLE;
    }

    read_value &= rd_mask;
    *out_rd_value = read_value;

    return TDX_SUCCESS;
}

api_error_code_e md_vp_read_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t value[MAX_ELEMENTS_IN_FIELD])
{
    // No special handling on read field

    // Currently, all VCPU fields have exactly one element
    if (entry->num_of_elem != 1)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    return md_vp_read_element(field_id, entry, access_type, access_qual, md_ctx, &value[0]);
}

/**
 *  Write a metadata element to memory based on its size (1, 2, 4 or 8 bytes)
 */
_STATIC_INLINE_ void write_element_to_mem(void* element_ptr, uint64_t value, uint32_t element_size_code)
{
    uint8_t  *ptr_8;
    uint16_t *ptr_16;
    uint32_t *ptr_32;
    uint64_t *ptr_64;
    switch (element_size_code)
    {
    case 0:  // 1 byte
        ptr_8 = (uint8_t *)element_ptr;
        *ptr_8 = (uint8_t) value;
        break;
    case 1:  // 2 bytes
        ptr_16 = (uint16_t *)element_ptr;
        *ptr_16 = (uint16_t) value;
        break;
    case 2:  // 4 bytes
        ptr_32 = (uint32_t *)element_ptr;
        *ptr_32 = (uint32_t) value;
        break;
    case 3:  // 8 bytes
        ptr_64 = (uint64_t *)element_ptr;
        *ptr_64 = value;
        break;

    default:
        FATAL_ERROR();
        break;
    }
}

static api_error_code_e md_vp_element_vmcs_wr_handle(md_field_id_t field_id, md_context_ptrs_t md_ctx,
                                                     uint64_t* wr_value, bool_t* write_done)
{
    *write_done = false;

    // Handle Special Cases
    //   - These are marked as RW* in the FAS TD VMCS tables
    //   - Shared PA values and their alignments were checked above
    switch (field_id.field_code)
    {
    case VMX_GUEST_CR0_ENCODE:
    {
        // CR0 value is written as if written by the guest TD.
        // No check of bit combination legality or cross-check with CR4 are done.  This means that a following
        // VM entry may fail; we support this for the relevant cases: debug and import.
        uint64_t old_cr, guest_host_mask, rd_shadow;
        ia32_vmread(VMX_GUEST_CR0_ENCODE, &old_cr);
        ia32_vmread(VMX_CR0_GUEST_HOST_MASK_ENCODE, &guest_host_mask);
        ia32_vmread(VMX_CR0_READ_SHADOW_ENCODE, &rd_shadow);

        if (!apply_cr0_cr4_controls_for_write(old_cr, wr_value, guest_host_mask, rd_shadow))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        break;
    }
    case VMX_GUEST_CR4_ENCODE:
    {
        // CR4 value is written as if written by the guest TD
        uint64_t old_cr, guest_host_mask, rd_shadow;
        ia32_vmread(VMX_GUEST_CR4_ENCODE, &old_cr);
        ia32_vmread(VMX_CR4_GUEST_HOST_MASK_ENCODE, &guest_host_mask);
        ia32_vmread(VMX_CR4_READ_SHADOW_ENCODE, &rd_shadow);

        if (!apply_cr0_cr4_controls_for_write(old_cr, wr_value, guest_host_mask, rd_shadow))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        // No need to check the compatibility of the CR4 value with the TD configuration.
        // This is implied by the guest/host mask and read shadow that were checked above.
        // We keep this check as a debug assertion.
        // The check does not apply for debug TDs
        tdx_debug_assert(md_ctx.tdcs_ptr->executions_ctl_fields.attributes.debug ||
                is_guest_cr4_allowed_by_td_config((ia32_cr4_t)*wr_value,
                md_ctx.tdcs_ptr->executions_ctl_fields.attributes,
                (ia32_xcr0_t)md_ctx.tdcs_ptr->executions_ctl_fields.xfam));

        break;
    }
    case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
    {
        if (!check_and_update_ia32_dbgctrl(wr_value, md_ctx.tdcs_ptr))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        break;
    }

    case VMX_NOTIFY_WINDOW_ENCODE:
    {
#ifdef L1_VM_DOS_POLICY_SUPPORT
        uint32_t l2_notify_window;
        vmx_procbased_ctls2_t shadow_procbased_exec_ctls2 =
                { .raw = md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[0] };

        if ((~(uint32_t)*wr_value != md_ctx.tdvps_ptr->management.shadow_notify_window[0]) &&
                shadow_procbased_exec_ctls2.notification_exiting)
        {
            // Combine the L1 policy to create the actual value in L2 VMCS
            for (uint16_t vm_id = 1; vm_id <= md_ctx.tdcs_ptr->management_fields.num_l2_vms; vm_id++)
            {
                l2_notify_window = crystal_clock_virt_to_real(md_ctx.tdvps_ptr->management.shadow_notify_window[vm_id]);
                if (shadow_procbased_exec_ctls2.notification_exiting)
                {
                    l2_notify_window = (l2_notify_window < (uint32_t)*wr_value) ? l2_notify_window : (uint32_t)*wr_value;
                }
                set_vm_vmcs_as_active(md_ctx.tdvps_ptr, vm_id);
                ia32_vmwrite(VMX_NOTIFY_WINDOW_ENCODE, l2_notify_window);
            }

            set_vm_vmcs_as_active(md_ctx.tdvps_ptr, 0);
        }
        // Save the written value (in real units) to the shadow
        md_ctx.tdvps_ptr->management.shadow_notify_window[0] = (uint32_t)*wr_value;
#endif
        break;
    }
    case VMX_VM_EXECUTION_CONTROL_PIN_BASED_ENCODE:
    {
        // Enabling posted interrupts in only allowed if the proper fields
        // have been initialized
        vmx_pinbased_ctls_t pinbased_exec_ctls;
        pinbased_exec_ctls.raw = (uint32_t)*wr_value;
        if (pinbased_exec_ctls.process_posted_interrupts == 1)
        {
            uint64_t addr, vec;

            ia32_vmread(VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE, &vec);

            if ((uint16_t)vec == POSTED_INTERRUPT_NOTFICATION_VECTOR_INIT)
            {
                return api_error_with_operand_id(TDX_TD_VMCS_FIELD_NOT_INITIALIZED,
                                                 VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE);
            }

            ia32_vmread(VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE, &addr);


            if (addr == (-1ULL))
            {
                return api_error_with_operand_id(TDX_TD_VMCS_FIELD_NOT_INITIALIZED,
                                                 VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE);
            }
        }

        md_ctx.tdvps_ptr->management.shadow_pinbased_exec_ctls = (uint32_t)pinbased_exec_ctls.raw;

        break;
    }
    case VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE:
    {
        md_ctx.tdvps_ptr->management.shadow_pid_hpa = *wr_value;
        break;
    }
    case VMX_POSTED_INTERRUPT_NOTIFICATION_VECTOR_ENCODE:
    {
        // although 'wr_value' is of type 'uint_64' and could never be negative, the first condition is here for code-completeness
        if (*wr_value < POSTED_INTERRUPT_NOTFICATION_VECTOR_MIN || *wr_value > POSTED_INTERRUPT_NOTFICATION_VECTOR_MAX)
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }
        else
        {
            // Save the notification vector in a shadow variable to avoid the need to read it from
            // L1 VMCS on L2 VM exit.
            md_ctx.tdvps_ptr->management.shadow_posted_int_notification_vector = (uint16_t)*wr_value;
        }

        break;
    }
    case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
    {
        vmx_procbased_ctls2_t new_ctls2;
        new_ctls2.raw = *wr_value;
        if (!check_l1_procbased_exec_ctls2(md_ctx.tdcs_ptr, new_ctls2))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

#ifdef L1_VM_DOS_POLICY_SUPPORT
        if ((uint32_t)new_ctls2.raw != md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[0])
        {
            // Since the host VMM is changing the TD's bus lock detections and/or notification settings,
            // We need to combine the L1 policy to create the actual value in L2 VMCS.
            for (uint16_t vm_id = 1; vm_id <= md_ctx.tdcs_ptr->management_fields.num_l2_vms; vm_id++)
            {
                set_vm_vmcs_as_active(md_ctx.tdvps_ptr, vm_id);

                vmx_procbased_ctls2_t l2_ctls2 = new_ctls2;
                vmx_procbased_ctls2_t shadow_ctls2 =
                    { .raw = md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[vm_id] };

                l2_ctls2.buslock_detect |= shadow_ctls2.buslock_detect;
                l2_ctls2.notification_exiting |= shadow_ctls2.notification_exiting;

                ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE, l2_ctls2.raw);

                // Update the L2 notification window
                uint32_t l2_notify_window = crystal_clock_virt_to_real(
                        md_ctx.tdvps_ptr->management.shadow_notify_window[vm_id]);
                if (new_ctls2.notification_exiting)
                {
                    l2_notify_window = MIN(l2_notify_window, md_ctx.tdvps_ptr->management.shadow_notify_window[0]);
                }

                ia32_vmwrite(VMX_NOTIFY_WINDOW_ENCODE, l2_notify_window);
            }

            set_vm_vmcs_as_active(md_ctx.tdvps_ptr, 0);
        }

        // Write the shadow value for easy access on VM exit from L2
        md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[0] = (uint32_t)new_ctls2.raw;
#endif

        break;
    }
    case VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE:
    {
        md_ctx.tdvps_ptr->management.shadow_shared_eptp[0] = *wr_value;

        break;
    }
    default:
        tdx_debug_assert(0); // The cases above should handle all special write handling.
        break;
    }

    return TDX_SUCCESS;
}

static api_error_code_e md_vp_element_l2_vmcs_wr_handle(md_field_id_t field_id, md_access_t access_type,
                                                        md_context_ptrs_t md_ctx, uint64_t read_value, uint64_t* wr_value,
                                                        bool_t* write_done)
{
    *write_done = false;

    uint16_t vm_id = md_vp_get_l2_vm_index(field_id.class_code);

    switch (field_id.field_code)
    {
    case VMX_CR0_GUEST_HOST_MASK_ENCODE:
    {
        // On L1 VMM write and on import, write the original value into the shadow, and
        // build the actual mask as a bitwise-or with the TD VCMS' mask.
        md_ctx.tdvps_ptr->management.shadow_cr0_guest_host_mask[vm_id] = *wr_value;

        // Combine the guest/host masks and read shadows and write the L2 VMCS
        combine_and_write_l2_cr0_controls(md_ctx.tdvps_ptr, vm_id);

        *write_done = true;
        break;
    }
    case VMX_CR0_READ_SHADOW_ENCODE:
    {
        md_ctx.tdvps_ptr->management.shadow_cr0_read_shadow[vm_id] = *wr_value;

        combine_and_write_l2_cr0_controls(md_ctx.tdvps_ptr, vm_id);

        *write_done = true;

        break;
    }
    case VMX_CR4_GUEST_HOST_MASK_ENCODE:
    {
        md_ctx.tdvps_ptr->management.shadow_cr4_guest_host_mask[vm_id] = *wr_value;

        combine_and_write_l2_cr4_controls(md_ctx.tdvps_ptr, vm_id);

        *write_done = true;

        break;
    }
    case VMX_CR4_READ_SHADOW_ENCODE:
    {
        md_ctx.tdvps_ptr->management.shadow_cr4_read_shadow[vm_id] = *wr_value;

        combine_and_write_l2_cr4_controls(md_ctx.tdvps_ptr, vm_id);

        *write_done = true;

        break;
    }
    case VMX_GUEST_EPT_POINTER_FULL_ENCODE:
    {
        ia32e_eptp_t eptp = { .raw = *wr_value };
        ia32_xcr0_t xfam = { .raw = md_ctx.tdcs_ptr->executions_ctl_fields.xfam };

        if (eptp.fields.enable_sss_control && !xfam.cet_s)
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        break;
    }
    case VMX_GUEST_CR0_ENCODE:
    {
        // L2 VM CR0 value is written using the base TDX policy for all L2 VMs
        uint64_t old_cr;
        ia32_vmread(VMX_GUEST_CR0_ENCODE, &old_cr);

        if (!apply_cr0_cr4_controls_for_write(old_cr, wr_value,
                md_ctx.tdvps_ptr->management.base_l2_cr0_guest_host_mask,
                md_ctx.tdvps_ptr->management.base_l2_cr0_read_shadow))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        break;
    }
    case VMX_GUEST_CR4_ENCODE:
    {
        // L2 VM CR4 value is written using the base TDX policy for all L2 VMs
        uint64_t old_cr;
        ia32_vmread(VMX_GUEST_CR4_ENCODE, &old_cr);

        if (!apply_cr0_cr4_controls_for_write(old_cr, wr_value,
                md_ctx.tdvps_ptr->management.base_l2_cr4_guest_host_mask,
                md_ctx.tdvps_ptr->management.base_l2_cr4_read_shadow))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        break;
    }
    case VMX_GUEST_IA32_DEBUGCTLMSR_FULL_ENCODE:
    {
        if (!check_and_update_ia32_dbgctrl(wr_value, md_ctx.tdcs_ptr))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }
        break;
    }
    case VMX_HLATP_FULL_ENCODE:
    {
        // Checking as private GPA was done before
        break;
    }
#ifdef L1_VM_DOS_POLICY_SUPPORT
    case VMX_NOTIFY_WINDOW_ENCODE:
    {
        // Save the written value (in virtual units) to the shadow
        md_ctx.tdvps_ptr->management.shadow_notify_window[vm_id] = (uint32_t)*wr_value;

        vmx_procbased_ctls2_t vmx_procbased_ctls2;
        vmx_procbased_ctls2.raw = md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[0];

        if (vmx_procbased_ctls2.notification_exiting)
        {
            // Set the window to the minimum of the values set by L1 and L2 to the L2 VMCS
            *wr_value = MIN(md_ctx.tdvps_ptr->management.shadow_notify_window[0],
                           crystal_clock_virt_to_real((uint32_t)*wr_value));
        }
        break;
    }
#endif
    case VMX_PAUSE_LOOP_EXITING_GAP_ENCODE:
    case VMX_PAUSE_LOOP_EXITING_WINDOW_ENCODE:
    {
        if ((access_type == MD_GUEST_WR) || (access_type == MD_IMPORT_IMMUTABLE))
        {
            // On writes by L1 VMM and on import, save the original value (in virtual TSC ticks) as a shadow
            // and convert to native TSC ticks.
            if (field_id.field_code == VMX_PAUSE_LOOP_EXITING_GAP_ENCODE)
            {
                md_ctx.tdvps_ptr->management.shadow_ple_gap[vm_id] = (uint32_t)*wr_value;
            }
            else
            {
                md_ctx.tdvps_ptr->management.shadow_ple_window[vm_id] = (uint32_t)*wr_value;
            }

            if (!calculate_native_tsc(*wr_value,
                                      md_ctx.tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                                      md_ctx.tdcs_ptr->executions_ctl_fields.tsc_offset,
                                      wr_value))
            {
                return TDX_METADATA_FIELD_VALUE_NOT_VALID;
            }

            // Check if the native value fits in 32 bits
            if (*wr_value >= BIT(32))
            {
                return TDX_METADATA_FIELD_VALUE_NOT_VALID;
            }
        }

        break;
    }
    case VMX_VM_EXECUTION_CONTROL_PROC_BASED_ENCODE:
    {
        vmx_procbased_ctls_t new_ctls = { .raw = *wr_value };
        vmx_procbased_ctls_t old_ctls = { .raw = read_value };
        if (!check_l2_procbased_exec_ctls(md_ctx.tdcs_ptr, old_ctls, new_ctls))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }
        break;
    }
    case VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE:
    {
        vmx_procbased_ctls2_t new_ctls2 = { .raw = *wr_value };
        vmx_procbased_ctls2_t old_ctls2 = { .raw = read_value };

        if (!check_l2_procbased_exec_ctls2(md_ctx.tdcs_ptr, old_ctls2, new_ctls2))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }

        // Save the write value to the shadow
        md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[vm_id] = (uint32_t)new_ctls2.raw;

#ifdef L1_VM_DOS_POLICY_SUPPORT

        // Combine the L1 policy to create the actual value in L2 VMCS
        vmx_procbased_ctls2_t l1_ctls2 = { .raw = md_ctx.tdvps_ptr->management.shadow_procbased_exec_ctls2[0] };
        new_ctls2.buslock_detect   |= l1_ctls2.buslock_detect;
        new_ctls2.notification_exiting |= l1_ctls2.notification_exiting;

        ia32_vmwrite(VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_ENCODE, new_ctls2.raw);

        if (new_ctls2.notification_exiting)
        {
            // Update the notification window
            uint32_t l2_notify_window =
                    crystal_clock_virt_to_real(md_ctx.tdvps_ptr->management.shadow_notify_window[vm_id]);
            if (l1_ctls2.notification_exiting)
            {
                l2_notify_window = MIN(l2_notify_window, md_ctx.tdvps_ptr->management.shadow_notify_window[0]);
            }

            ia32_vmwrite(VMX_NOTIFY_WINDOW_ENCODE, l2_notify_window);
        }

        *write_done = true;

#endif

        break;
    }
    case VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE:
    {
        md_ctx.tdvps_ptr->management.shadow_shared_eptp[vm_id] = *wr_value;
        if (!md_ctx.tdvps_ptr->management.l2_ctls[vm_id].enable_shared_eptp)
        {
            *write_done = true;
        }

        break;
    }
    case VMX_VIRTUAL_APIC_PAGE_ADDRESS_FULL_ENCODE:
    {
        // Checking as private GPA was done before

        md_ctx.tdvps_ptr->management.l2_vapic_gpa[vm_id] = *wr_value;
        md_ctx.tdvps_ptr->management.l2_vapic_hpa[vm_id] = NULL_PA;
        *write_done = true;
        break;
    }
#ifdef L2_VE_SUPPORT
    case VMX_VIRTUAL_EXCEPTION_INFO_ADDRESS_FULL_ENCODE:
    {
        // Checking as private GPA was done before

        md_ctx.tdvps_ptr->management.ve_info_gpa[vm_id] = *wr_value;
        md_ctx.tdvps_ptr->management.ve_info_hpa[vm_id] = NULL_PA;
        *write_done = true;
        break;
    }
#endif
    default:
        tdx_debug_assert(0); // The cases above should handle all special write handling.
        break;
    }

    return TDX_SUCCESS;
}

static api_error_code_e md_vp_element_tdvps_wr_handle(md_field_id_t field_id, md_access_t access_type,
                                                      md_context_ptrs_t md_ctx, uint64_t* wr_value, bool_t* write_done)
{
    *write_done = false;

    switch (field_id.class_code)
    {
        case MD_TDVPS_GUEST_STATE_CLASS_CODE:
        {
            if (field_id.field_code == MD_TDVPS_XCR0_FIELD_CODE)
            {
                if (!check_guest_xcr0_value((ia32_xcr0_t)*wr_value, md_ctx.tdcs_ptr->executions_ctl_fields.xfam))
                {
                    return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                }
            }
            else
            {
                tdx_debug_assert(0);
            }
            break;
        }
        case MD_TDVPS_GUEST_EXT_STATE_CLASS_CODE:
        {
            // Prevent the host VMM from writing the XSAVE header (only applicable for DEBUG TDs).
            // The XSAVE header starts after XSAVE legacy region, and is 64 bytes long.
            // As metadata the element size is 8 bytes.
            if (access_type == MD_HOST_WR)
            {
                if ((field_id.field_code >= (sizeof(xsave_legacy_region_t) / 8)) &&
                    (field_id.field_code < ((sizeof(xsave_legacy_region_t) + sizeof(xsave_header_t)) / 8)))
                {
                    return TDX_METADATA_FIELD_NOT_WRITABLE;
                }
            }
            break;
        }
        case MD_TDVPS_GUEST_MSR_STATE_CLASS_CODE:
        {
            if (field_id.field_code == MD_TDVPS_IA32_SPEC_CTRL_FIELD_CODE)
            {
                *wr_value = calculate_real_ia32_spec_ctrl(md_ctx.tdcs_ptr, *wr_value);
            }
            else
            {
                tdx_debug_assert(0);
            }
            break;
        }
        case MD_TDVPS_MANAGEMENT_CLASS_CODE:
        {
            switch (field_id.field_code)
            {
                case MD_TDVPS_XFAM_FIELD_CODE:
                {
                    if (!check_xfam((ia32_xcr0_t)*wr_value))
                    {
                        return TDX_METADATA_FIELD_VALUE_NOT_VALID;
                    }
                    break;
                }
                case MD_TDVPS_L2_CTLS_FIELD_CODE:
                {
                    // No L2 CTLS is supported for VM #0, ignore
                    break;
                }
                case (MD_TDVPS_L2_CTLS_FIELD_CODE + 1):
                case (MD_TDVPS_L2_CTLS_FIELD_CODE + 2):
                case (MD_TDVPS_L2_CTLS_FIELD_CODE + 3):
                {
                    uint16_t vm_id = (uint16_t)(field_id.field_code - MD_TDVPS_L2_CTLS_FIELD_CODE);
                    if(vm_id > md_ctx.tdcs_ptr->management_fields.num_l2_vms)
                    {
                        // No L2 CTLS is supported for non-existant VM, ignore
                        break;
                    }

                    l2_vcpu_ctrl_t l2_ctls = { .raw = *wr_value };

                    set_vm_vmcs_as_active(md_ctx.tdvps_ptr, vm_id);

                    if (l2_ctls.enable_shared_eptp &&
                        (md_ctx.tdvps_ptr->management.shadow_shared_eptp[vm_id] != NULL_PA))
                    {
                        // Shared EPTP is enable, write the shadow value to VMCS
                        ia32_vmwrite(VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE,
                                md_ctx.tdvps_ptr->management.shadow_shared_eptp[vm_id]);
                    }
                    else
                    {
                        // Shared EPTP is disabled, point it to the TDCS' zero page
                        ia32_vmwrite(VMX_GUEST_SHARED_EPT_POINTER_FULL_ENCODE,
                                md_ctx.tdr_ptr->management_fields.tdcx_pa[ZERO_PAGE_INDEX]);
                    }
                    break;
                }
                case MD_TDVPS_TSC_DEADLINE_FIELD_CODE:
                {
                    // No TSC deadline is supported for VM #0, ignore
                    break;
                }
                case (MD_TDVPS_TSC_DEADLINE_FIELD_CODE + 1):
                case (MD_TDVPS_TSC_DEADLINE_FIELD_CODE + 2):
                case (MD_TDVPS_TSC_DEADLINE_FIELD_CODE + 3):
                {
                    uint16_t vm_id = (uint16_t)(field_id.field_code - MD_TDVPS_TSC_DEADLINE_FIELD_CODE);
                    if(vm_id > md_ctx.tdcs_ptr->management_fields.num_l2_vms)
                    {
                        // No TSC deadline is supported for non-existant VM, ignore
                        break;
                    }

                    if (*wr_value != ~(0ULL))
                    {
                        // TSC deadline is enabled.  Set the shadow value in native TSC units.

                        uint64_t native_tsc = ia32_rdtsc();
                        uint64_t virt_tsc = calculate_virt_tsc(native_tsc,
                                                               md_ctx.tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                                                               md_ctx.tdcs_ptr->executions_ctl_fields.tsc_offset);

                        /* Check if the TSC deadline is in the past.  Remmeber that the TD's virtual TSC starts from 0 and
                           can't practically wrap around, so we can do a simple comparison. */
                        uint64_t native_tsc_deadline = 0;
                        if (*wr_value <= virt_tsc)
                        {
                            // Deadline is in the past.  Set the deadline to the current native TSC value.
                            native_tsc_deadline = native_tsc;
                        }
                        else
                        {
                            if (!calculate_native_tsc(*wr_value,
                                                      md_ctx.tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                                                      md_ctx.tdcs_ptr->executions_ctl_fields.tsc_offset,
                                                      &native_tsc_deadline))
                            {
                                return TDX_OPERAND_INVALID;
                            }

                            if (0 == native_tsc_deadline)
                            {
                                return TDX_OPERAND_INVALID;
                            }

                            // If there was a wraparound, then it's an error.  Deadline was requested too far in the future.
                            if ((int64_t)(native_tsc_deadline - native_tsc) < 0)
                            {
                                return TDX_OPERAND_INVALID;
                            }
                        }

                        md_ctx.tdvps_ptr->management.shadow_tsc_deadline[vm_id] = native_tsc_deadline;
                    }
                    break;
                }
                default: tdx_debug_assert(0);
            }
            break;
        }
        case MD_TDVPS_MSR_BITMAPS_1_CLASS_CODE:
        case MD_TDVPS_MSR_BITMAPS_2_CLASS_CODE:
        case MD_TDVPS_MSR_BITMAPS_3_CLASS_CODE:
        {
            uint16_t vm_id = md_vp_get_l2_vm_index(field_id.class_code);

            if (vm_id > md_ctx.tdcs_ptr->management_fields.num_l2_vms)
            {
                return TDX_METADATA_FIELD_ID_INCORRECT;
            }

            // Write the value to the shadow page
            md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_shadow_msr_bitmaps[field_id.field_code] = *wr_value;
            *write_done = true;

            // Write the real MSR bitmaps page used by the CPU
            uint32_t msr_index = get_msr_index_from_shadow_msr_bitmap_field_id(field_id);

            if ((msr_index >= IA32_X2APIC_START) && (msr_index <= IA32_X2APIC_END))
            {
                // For X2APIC MSRs, the MSR bitmaps value is directly written
                md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_msr_bitmaps[field_id.field_code] = *wr_value;
            }
            else
            {
                // The MSR bitmaps value is a bitwise - or of the TD's MSR bitmaps value and the shadow value.
                // Map the TD's MSR bitmaps page (it is typically unmapped).
                uint64_t* td_msr_bitmaps_page_p = (uint64_t*)md_ctx.tdcs_ptr->MSR_BITMAPS;
                md_ctx.tdvps_ptr->l2_vm_ctrl[vm_id-1].l2_msr_bitmaps[field_id.field_code] =
                        td_msr_bitmaps_page_p[field_id.field_code] | *wr_value;
            }

            break;
        }
        default: tdx_debug_assert(0);
    }

    return TDX_SUCCESS;
}

static api_error_code_e md_vp_element_special_wr_handle(md_field_id_t field_id, md_access_t access_type,
                                                        md_context_ptrs_t md_ctx, uint64_t read_value,
                                                        uint64_t* wr_value, bool_t* write_done)
{
    api_error_code_e retval = TDX_SUCCESS;
    *write_done = false;

    if (field_id.class_code == MD_TDVPS_VMCS_CLASS_CODE)
    {
        retval = md_vp_element_vmcs_wr_handle(field_id, md_ctx, wr_value, write_done);
    }
    else if ((field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE) ||
             (field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE) ||
             (field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE))
    {
        retval = md_vp_element_l2_vmcs_wr_handle(field_id, access_type, md_ctx, read_value, wr_value, write_done);
    }
    else
    {
        retval = md_vp_element_tdvps_wr_handle(field_id, access_type, md_ctx, wr_value, write_done);
    }

    return retval;
}

_STATIC_INLINE_ uint64_t md_vp_get_checked_size_of_shared_hpa_range(md_field_id_t field_id)
{
    uint64_t size = TDX_PAGE_SIZE_IN_BYTES;
    if ((field_id.class_code == MD_TDVPS_VMCS_CLASS_CODE ||
         field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE ||
         field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE ||
         field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE) &&
         field_id.field_code == VMX_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL_ENCODE)
    {
        size = POSTED_INTER_DESCRIPTOR_SIZE;
    }

    return size;
}

// Adjust current field value per field attributes
//  Used for handling fields whose initial value is special and contradict normal write rules
//  Currently supported:
//  - Handling of any PA:  special handling of NULL_PA (-1)
static uint64_t md_vp_adjust_value_per_field_attr_on_wr(const md_lookup_t* entry, uint64_t current_value,
                                                        uint64_t wr_mask)
{
    // Initial value of a physical address is NULL_PA (-1).
    // When writing a new value, we need to clear bits that are not part of the write mask.
    IF_RARE ((entry->attributes.gpa || entry->attributes.hpa) && is_initial_invalid_pa(current_value))
    {
        current_value &= wr_mask;
    }

    return current_value;
}

static api_error_code_e md_vp_handle_field_attribute_on_wr(md_field_id_t field_id, const md_lookup_t* entry,
                                                           md_context_ptrs_t md_ctx, uint64_t* wr_value)
{
    if (entry->attributes.hpa && entry->attributes.shared)
    {
        uint64_t size = md_vp_get_checked_size_of_shared_hpa_range(field_id);

        if (shared_hpa_check((pa_t)*wr_value, size) != TDX_SUCCESS)
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }
    }
    else if (entry->attributes.gpa && entry->attributes.prvate)
    {
        if (!check_gpa_validity((pa_t)*wr_value, md_ctx.tdcs_ptr->executions_ctl_fields.gpaw, PRIVATE_ONLY))
        {
            return TDX_METADATA_FIELD_VALUE_NOT_VALID;
        }
    }

    return TDX_SUCCESS;
}

api_error_code_e md_vp_write_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx, uint64_t wr_value, uint64_t wr_request_mask,
        uint64_t* old_value, bool_t return_old_val)
{
    uint64_t rd_mask, wr_mask, combined_wr_mask, read_value = 0;
    uint64_t tmp_old_value = 0;
    uint64_t* elem_ptr;
    api_error_code_e status;

    status = md_vp_get_element(field_id, entry, access_type, access_qual, md_ctx, &rd_mask, &wr_mask,
                               &tmp_old_value, &elem_ptr);

    if (status != TDX_SUCCESS)
    {
        return status;
    }

    // Narrow down the bits to be written with the input mask
    combined_wr_mask = wr_mask & wr_request_mask;

    // Check if the requested field is writable.
    // Note that there is no check for readable; we don't have write-only
    // fields.
    if (combined_wr_mask == 0)
    {
        return TDX_METADATA_FIELD_NOT_WRITABLE;
    }

    uint64_t element_size_mask = md_get_element_size_mask(entry->field_id.element_size_code);

    // If the whole element is written (e.g., on import), keep rd_value as 0.
    // This is used when inserting wr_value bits later.
    // This prevents the need to handle conversion on read that might introduce errors.
    if (combined_wr_mask != element_size_mask)
    {
        read_value = tmp_old_value;
    }

    // Mask the value to be returned at the end with the read mask
    tmp_old_value &= rd_mask;

    read_value = md_vp_adjust_value_per_field_attr_on_wr(entry, read_value, wr_mask);

    if (!md_check_forbidden_bits_unchanged(read_value, wr_value, wr_request_mask, wr_mask))
    {
        return TDX_METADATA_FIELD_VALUE_NOT_VALID;
    }

    // Insert the bits to be written
    wr_value = (read_value & ~combined_wr_mask) | (wr_value & combined_wr_mask);

    // Check additional requirements on the value to be written
    status = md_vp_handle_field_attribute_on_wr(field_id, entry, md_ctx, &wr_value);
    if (status != TDX_SUCCESS)
    {
        return status;
    }

    bool_t write_done = false;

    if (entry->special_wr_handling)
    {
        status = md_vp_element_special_wr_handle(field_id, access_type, md_ctx, read_value, &wr_value, &write_done);
        if (status != TDX_SUCCESS)
        {
            return status;
        }
    }

    if ((field_id.class_code == MD_TDVPS_VMCS_CLASS_CODE) ||
        (field_id.class_code == MD_TDVPS_VMCS_1_CLASS_CODE) ||
        (field_id.class_code == MD_TDVPS_VMCS_2_CLASS_CODE) ||
        (field_id.class_code == MD_TDVPS_VMCS_3_CLASS_CODE))
    {
        // VMWRITE may fail if the field is read-only but the write mask allowed write.
        if (!write_done)
        {
            if (!ia32_try_vmwrite(field_id.field_code, wr_value))
            {
                return TDX_METADATA_FIELD_NOT_WRITABLE;
            }
        }
    }
    else
    {
        tdx_debug_assert(elem_ptr != NULL);
        // Write the value
        if (!write_done)
        {
            write_element_to_mem(elem_ptr, wr_value, entry->field_id.element_size_code);
        }
    }

    if (return_old_val)
    {
        *old_value = tmp_old_value;
    }

    return TDX_SUCCESS;
}

api_error_code_e md_vp_write_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
                                   md_access_qualifier_t access_qual, md_context_ptrs_t md_ctx,
                                   uint64_t value[MAX_ELEMENTS_IN_FIELD], uint64_t wr_mask)
{
    // No special handling on read field

    // Currently, all VCPU fields have exactly one element
    if (entry->num_of_elem != 1)
    {
        return TDX_METADATA_FIELD_ID_INCORRECT;
    }

    uint64_t old_value;

    return md_vp_write_element(field_id, entry, access_type, access_qual, md_ctx, value[0], wr_mask, &old_value, false);
}

