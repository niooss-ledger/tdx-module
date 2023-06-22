/**
 * @file exception_handling_asm_S
 * @brief Assembly code implementation of exception handlers
 */

#include "exception_handling_consts.h"

/**
 * Data stack after exception handler entry:
 * [       ...       ] <- RSP before exception
 * [     Spare 64    ] +48
 * [ Saved SS = 0x10 ] +40
 * [     Old RSP     ] +32
 * [    Old RFLAGS   ] +24
 * [ Saved CS = 0x8  ] +16
 * [   Faulting RIP  ] +8
 * [    Error code   ] +0 <- Current RSP after exception
 *
 * For exceptions that don't deliver error code, Current RSP will point at the "Faulting RIP"
 */

.section .text

#define CORRUPT_ADDRESS                                 (1ULL << 63) // Non-canonical Linear Address

#define EXCEPTION_HANDLER(func)                         endbr64;            /* 4 bytes */ \
                                                        jmp func;           /* 5 bytes */\
                                                        /* 7 nops to fill 7 bytes to complete 16 bytes */\
                                                        nop; nop; nop; nop; \
                                                        nop; nop; nop; \

#define UNSUPPORTED_EXCEPTION_HANDLERS

.globl tdx_fault_wrapper
.type  tdx_fault_wrapper,@function
tdx_fault_wrapper:

    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 0
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 1
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 2
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 3
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 4
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 5
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 6
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 7
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 8
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 9
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 10
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 11
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 12
    EXCEPTION_HANDLER(tdx_gp_handler)                 // Vector 13 - #GP
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 14
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 15
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 16
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 17
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 18
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 19
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 20
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 21
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 22
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 23
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 24
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 25
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 26
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 27
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 28
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 29
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 30
    EXCEPTION_HANDLER(tdx_unsupported_handler)        // Vector 31

    ud2


tdx_unsupported_handler:
    // This a generic handler for unsupported exception type
    // Initiate SEAM shutdown with a Triple Fault

    movq $CORRUPT_ADDRESS, %rsp            // Corrupt stack pointer
    movq $0, %rax
    jmpq *%rax                             // Jump to non-mapped address

    ud2


tdx_gp_handler:

    addq $0x8, %rsp                        // Discard error code

    movq (%rsp), %rsi                      // Get the faulting RIP
    movq -8(%rsi), %rsi                    // Read the magic indicator

    movq $FAULT_SAFE_MAGIC_INDICATOR, %rax

    xorq %rax, %rsi                        // Check indicator validity
    jz   indicator_valid                   // If not correct - Initiate SEAM shutdown

    movq $CORRUPT_ADDRESS, %rsp            // Corrupt stack pointer
    movq $0, %rax
    jmpq *%rax                             // Jump to non-mapped address

indicator_valid:

    movq $NON_FAULTING_MSR_ADDR, %rcx      // Non-faulting MSR index
    movq $0x0, %rax                        // Non-faulting value low
    movq $0x0, %rdx                        // Non-faulting value high

    // Check how much bytes we need to pop from the stack
    // If the old stack wasn't aligned on 16-bytes, "Spare 64" will be inserted to align it

    btq  $3, 24(%rsp)                      // Check if old stack was aligned on 8 or 16 bytes
    jc aligned_stack_ret

    lretq $32

    ud2

aligned_stack_ret:

    lretq $24

    ud2
