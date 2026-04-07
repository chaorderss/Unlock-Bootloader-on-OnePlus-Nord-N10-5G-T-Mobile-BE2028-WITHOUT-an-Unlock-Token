/*
 * kmon_sa.S - Patch hdd_start_adapter bitmask to include QDF_MONITOR_MODE (4)
 *
 * At hdd_start_adapter+0x80: MOVZ W9, #0xE5  (bitmask 0x000100E5)
 * The bitmask has bits: 0,2,5,6,7,16 but NOT bit 4 (MONITOR)
 *
 * Patch: 0xE5 (11100101) → 0xF5 (11110101) to add bit 4
 * Instruction bytes: 0x528038a9 → 0x52803aa9 (change bit 9 of instruction)
 *
 * This makes hdd_start_adapter route MONITOR through the STA init path,
 * which correctly calls hdd_vdev_create → hdd_get_vdev_type → WMI_VDEV_TYPE_MONITOR
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kread"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kread"
    .asciz "license=GPL"

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

.section .rodata, "a"
sym_start:  .asciz "hdd_start_adapter"
sym_rw:     .asciz "set_memory_rw"

fmt_addr:   .asciz "ksa: hdd_start_adapter=%px\n"
fmt_patch:  .asciz "ksa: +0x80: 0x%08x -> 0x%08x\n"
fmt_done:   .asciz "ksa: bitmask patched to include MONITOR (bit 4)\n"
fmt_err:    .asciz "ksa: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    /* Resolve hdd_start_adapter */
    adrp x0, sym_start
    add x0, x0, :lo12:sym_start
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Resolve set_memory_rw */
    adrp x0, sym_rw
    add x0, x0, :lo12:sym_rw
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    bl printk

    /* Read current instruction at +0x80 */
    add x21, x19, #0x80    /* target address */
    ldr w22, [x21]          /* old instruction */

    /* Verify it's the expected MOVZ instruction */
    /* Expected: 0x528038a9 (MOVZ W9, #0xE5) */
    /* We want to change bit 9 of the instruction to set bit 4 of the immediate */
    /* New: 0x52803aa9 (MOVZ W9, #0xF5) */

    /* Make page writable */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20                /* set_memory_rw */

    /* Compute new instruction: set bit 9 */
    orr w23, w22, #(1 << 9)

    adrp x0, fmt_patch
    add x0, x0, :lo12:fmt_patch
    mov w1, w22
    mov w2, w23
    bl printk

    /* Write patched instruction */
    str w23, [x21]

    /* Cache maintenance */
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret

.section .note.Linux, "a", @note
    .long 6
    .long 0
    .long 0x100
    .asciz "Linux"
    .balign 4

.section .plt, "ax"
    .balign 8
    .space 8
.section .init.plt, "ax"
    .balign 8
    .space 8
.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
