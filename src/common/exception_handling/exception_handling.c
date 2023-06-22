/**
 * @file exception_handling.c
 * @brief Exception handling for TDX module. IDT, GDT and exception handler definitions
 */

#include "exception_handling.h"

#define TDX_MODULE_CS_SELECTOR        0x8U


const idt_and_gdt_tables_t tdx_idt_and_gdt_tables =
{
    .idt_table =
    {
        // #GP handler - the only exception currently supported
        [13] = {
                  .selector = TDX_MODULE_CS_SELECTOR, .gate_type = IA32_IDT_GATE_TYPE_INTERRUPT_32,
                  .present = 1
               }

        // All other entries and bits are filled with zeroes by default
    },

    .gdt_table =
    {
        [1] = {
                  .type = CODE_SEGMENT_TYPE_WITH_CRA_BITS, .s = 1, .p = 1, .l = 1
              }

        // All other entries are filled with zeroes by default
    }
};


