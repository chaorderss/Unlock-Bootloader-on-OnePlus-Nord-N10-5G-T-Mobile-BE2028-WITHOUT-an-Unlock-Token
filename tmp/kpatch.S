/*
 * kpatch.S - Minimal AArch64 kernel module to patch nl80211_tx_mgmt
 *
 * Patches the iftype bitmask to add MONITOR mode for management frame TX.
 * Changes MOVZ W11, #0x39e to MOVZ W11, #0x3de at nl80211_tx_mgmt+0x74
 *
 * Build: as -o kpatch.o kpatch.S && ld -r -o kpatch.ko kpatch.o
 * Load:  insmod kpatch.ko
 * Unload: rmmod kpatch
 */

/* ============== .modinfo ============== */
.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kpatch"
    .asciz "license=GPL"
    .asciz "description=Patch nl80211_tx_mgmt monitor TX bitmask"

/* ============== __versions (symbol CRCs) ============== */
/* Each entry: 8 bytes CRC + 56 bytes name (null-padded) */
/* CONFIG_MODULE_FORCE_LOAD=y so CRCs don't matter */
.section __versions, "a"
    .quad 0
    .asciz "module_layout"
    .balign 64, 0
    .quad 0
    .asciz "printk"
    .balign 64, 0
    .quad 0
    .asciz "kallsyms_lookup_name"
    .balign 64, 0
    .quad 0
    .asciz "set_memory_rw"
    .balign 64, 0
    .quad 0
    .asciz "set_memory_ro"
    .balign 64, 0

/* ============== .rodata.str1.1 ============== */
.section .rodata.str1.1, "aMS", @progbits, 1
func_name:
    .asciz "nl80211_tx_mgmt"
init_ok_msg:
    .asciz "\001kpatch: monitor TX bitmask patched (0x39e -> 0x3de)\n"
init_fail_msg:
    .asciz "\001kpatch: FAILED - unexpected instruction at target\n"
init_notfound_msg:
    .asciz "\001kpatch: FAILED - nl80211_tx_mgmt not found\n"
init_rwfail_msg:
    .asciz "\001kpatch: FAILED - set_memory_rw failed\n"
exit_msg:
    .asciz "\001kpatch: monitor TX bitmask restored\n"

/* ============== .data ============== */
.section .data
.balign 8
saved_addr:
    .quad 0     /* saved address of the patched instruction */

/* ============== .init.text (init_module) ============== */
.section .init.text, "ax"
.globl init_module
.type init_module, @function
init_module:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    stp x20, x19, [sp, #16]
    str x21, [sp, #32]

    /* Call kallsyms_lookup_name("nl80211_tx_mgmt") */
    adrp x0, func_name
    add x0, x0, :lo12:func_name
    bl kallsyms_lookup_name

    /* Check if found */
    cbz x0, .Lnotfound

    /* x19 = nl80211_tx_mgmt + 0x74 (the MOVZ instruction) */
    add x19, x0, #0x74

    /* Save address for cleanup_module */
    adrp x8, saved_addr
    add x8, x8, :lo12:saved_addr
    str x19, [x8]

    /* Page-align for set_memory_rw */
    and x20, x19, #0xfffffffffffff000

    /* set_memory_rw(page, 1) */
    mov x0, x20
    mov w1, #1
    bl set_memory_rw
    cbnz w0, .Lrwfail

    /* Read current instruction */
    ldr w8, [x19]

    /* Build expected value: 0x528073cb */
    mov w9, #0x73cb
    movk w9, #0x5280, lsl #16

    /* Compare */
    cmp w8, w9
    b.ne .Lbadinsn

    /* Write new value: 0x52807bcb */
    mov w8, #0x7bcb
    movk w8, #0x5280, lsl #16
    str w8, [x19]

    /* Flush instruction cache */
    dc cvau, x19
    dsb ish
    ic ivau, x19
    dsb ish
    isb

    /* Restore RO */
    mov x0, x20
    mov w1, #1
    bl set_memory_ro

    /* Print success */
    adrp x0, init_ok_msg
    add x0, x0, :lo12:init_ok_msg
    bl printk

    /* Return 0 */
    mov w0, #0
    b .Lepilogue

.Lnotfound:
    adrp x0, init_notfound_msg
    add x0, x0, :lo12:init_notfound_msg
    bl printk
    mov w0, #-1
    b .Lepilogue

.Lrwfail:
    adrp x0, init_rwfail_msg
    add x0, x0, :lo12:init_rwfail_msg
    bl printk
    mov w0, #-1
    b .Lepilogue

.Lbadinsn:
    /* Restore RO before failing */
    mov x0, x20
    mov w1, #1
    bl set_memory_ro

    adrp x0, init_fail_msg
    add x0, x0, :lo12:init_fail_msg
    bl printk
    mov w0, #-1

.Lepilogue:
    ldr x21, [sp, #32]
    ldp x20, x19, [sp, #16]
    ldp x29, x30, [sp], #48
    ret
.size init_module, . - init_module

/* ============== .exit.text (cleanup_module) ============== */
.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, @function
cleanup_module:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x20, x19, [sp, #16]

    /* Load saved address */
    adrp x0, saved_addr
    add x0, x0, :lo12:saved_addr
    ldr x19, [x0]

    /* If never patched, skip */
    cbz x19, .Lexit_done

    /* Page-align */
    and x20, x19, #0xfffffffffffff000

    /* set_memory_rw */
    mov x0, x20
    mov w1, #1
    bl set_memory_rw
    cbnz w0, .Lexit_done

    /* Restore original: 0x528073cb */
    mov w8, #0x73cb
    movk w8, #0x5280, lsl #16
    str w8, [x19]

    /* Flush icache */
    dc cvau, x19
    dsb ish
    ic ivau, x19
    dsb ish
    isb

    /* Restore RO */
    mov x0, x20
    mov w1, #1
    bl set_memory_ro

    /* Print */
    adrp x0, exit_msg
    add x0, x0, :lo12:exit_msg
    bl printk

.Lexit_done:
    ldp x20, x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size cleanup_module, . - cleanup_module

/* ============== .gnu.linkonce.this_module ============== */
.section ".gnu.linkonce.this_module", "aw"
.balign 256
__this_module:
    .fill 24, 1, 0             /* state, pad: bytes 0-23 */
    .asciz "kpatch"            /* name: bytes 24-30 */
    .fill 49, 1, 0             /* pad name to 56 bytes: bytes 31-79 */
    .fill 256, 1, 0            /* pad to offset 0x150 (336): bytes 80-335 */
    .quad init_module          /* init at offset 0x150=336: relocation generated */
    .fill 440, 1, 0            /* pad to offset 0x310 (784): bytes 344-783 */
    .quad cleanup_module       /* exit at offset 0x310=784: relocation generated */
    .fill 40, 1, 0             /* pad to 0x340 (832): bytes 792-831 */

/* Relocations for this_module init/exit are done by the linker */
/* since init_module and cleanup_module are global symbols */

/* ============== .note.Linux ============== */
.section .note.Linux, "a", @note
    .long 6         /* namesz */
    .long 0         /* descsz */
    .long 0x100     /* type: MODULE */
    .asciz "Linux"
    .balign 4

/* ============== PLT sections (required by ARM64 module loader) ============== */
.section .plt, "aw"
    .balign 8
    .space 8

.section .init.plt, "aw"
    .balign 8
    .space 8

.section .text.ftrace_trampoline, "aw"
    .balign 8
    .space 8
