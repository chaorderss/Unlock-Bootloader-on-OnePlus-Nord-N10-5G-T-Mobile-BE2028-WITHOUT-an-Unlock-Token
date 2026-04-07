/*
 * kmon7.S - Monitor mode: patch change_iface bitmask + jump table
 *
 * 1. change_iface+0x180: bitmask 0xA5 → 0xE5 (add BIT(6) for MONITOR)
 * 2. Jump table byte[5] at table_base+5: 0x81 → 0x65 (route MONITOR to STA handler)
 *
 * (convert_nl_iftype bitmask+table already patched by kmon6)
 *
 * Build: as -o kmon7.o kmon7.S && ld -r -o kmon7.ko kmon7.o
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

.section .rodata, "a"
sym_chg:    .asciz "wlan_hdd_cfg80211_change_iface"
sym_rwx:    .asciz "set_memory_rw"

fmt_a:      .asciz "kmon7: change_iface=%px\n"
fmt_p1:     .asciz "kmon7: bitmask +0x180: 0x%08x -> 0x%08x\n"
fmt_p2:     .asciz "kmon7: jt byte[5] @ %px: 0x%02x -> 0x%02x\n"
fmt_err:    .asciz "kmon7: error\n"
fmt_done:   .asciz "kmon7: DONE\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    /* Resolve change_iface */
    adrp x0, sym_chg
    add x0, x0, :lo12:sym_chg
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Resolve set_memory_rw */
    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    adrp x0, fmt_a
    add x0, x0, :lo12:fmt_a
    mov x1, x19
    bl printk

    /* ---- PATCH 1: bitmask at change_iface+0x180 ---- */
    /* MOVZ W9, #0xA5 (0x528014a9) → MOVZ W9, #0xE5 (0x52801ca9) */
    add x21, x19, #0x180

    /* set_memory_rw for text page */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    ldr w22, [x21]              /* old instruction */

    /* Write MOVZ W9, #0xE5 */
    mov w23, #0x1ca9
    movk w23, #0x5280, lsl #16
    str w23, [x21]
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    adrp x0, fmt_p1
    add x0, x0, :lo12:fmt_p1
    mov w1, w22
    mov w2, w23
    bl printk

    /* ---- PATCH 2: jump table byte[5] ---- */
    /* Decode ADRP at change_iface+0x19c and ADD at +0x1a0 */
    ldr w22, [x19, #0x19c]      /* ADRP instruction */
    ubfx w23, w22, #5, #19
    ubfx w24, w22, #29, #2
    orr w23, w24, w23, lsl #2
    sbfx x23, x23, #0, #21
    lsl x23, x23, #12

    add x24, x19, #0x19c
    and x24, x24, #~0xFFF
    add x23, x23, x24            /* target page */

    ldr w22, [x19, #0x1a0]      /* ADD instruction */
    ubfx w24, w22, #10, #12
    add x23, x23, x24            /* x23 = table_base */

    /* byte[5] at table_base + 5 */
    add x21, x23, #5

    /* set_memory_rw for data page */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    ldrb w22, [x21]             /* old byte */

    /* Write 0x65 (same as STA handler) */
    mov w23, #0x65
    strb w23, [x21]
    dc cvau, x21
    dsb ish

    ldrb w24, [x21]             /* verify */
    adrp x0, fmt_p2
    add x0, x0, :lo12:fmt_p2
    mov x1, x21
    mov w2, w22
    mov w3, w24
    bl printk

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1                  /* don't stay loaded */
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
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
