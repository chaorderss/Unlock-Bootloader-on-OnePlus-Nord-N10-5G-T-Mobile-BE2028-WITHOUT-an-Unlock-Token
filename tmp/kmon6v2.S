/*
 * kmon6.S - Monitor mode enabler (hardcoded addresses, no ADRP decode)
 *
 * The function uses W8 = iftype - 1 for indexing:
 *   MONITOR = iftype 6, so W8 = 5
 *   Bitmask bit 5 = 0x20 needed
 *   Table index [5] = QDF_MONITOR_MODE = 4
 *
 * Patches:
 * 1. func+0x10: MOVZ W9, #0x187 (or #0x1C7) → MOVZ W9, #0x1A7
 * 2. table[5] at 0xffffff93c959f1bc: 0 → 4
 *
 * Build: as -o kmon6.o kmon6.S && ld -r -o kmon6.ko kmon6.o
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
sym_conv:   .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
sym_rwx:    .asciz "set_memory_rw"

fmt_a:      .asciz "kmon6: conv=%px\n"
fmt_p1:     .asciz "kmon6: bitmask: 0x%08x -> 0x%08x\n"
fmt_p2:     .asciz "kmon6: table[5] @ %px: %d -> %d\n"
fmt_err:    .asciz "kmon6: error\n"
fmt_done:   .asciz "kmon6: DONE\n"

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

    /* Resolve symbols */
    adrp x0, sym_conv
    add x0, x0, :lo12:sym_conv
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    adrp x0, fmt_a
    add x0, x0, :lo12:fmt_a
    mov x1, x19
    bl printk

    /* ---- PATCH 1: bitmask at func+0x10 ---- */
    add x21, x19, #0x10         /* target addr */

    /* set_memory_rw */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    ldr w22, [x21]              /* old value */

    /* Write MOVZ W9, #0x1A7 = 0x528034e9 */
    mov w23, #0x34e9
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

    /* ---- PATCH 2: table[5] ---- */
    /* Calculate table address from ADRP+ADD at func+0x50/0x54 */
    /* ADRP at +0x50 decoded: page = func_page + imm21<<12 */
    /* Instead of decoding, use runtime calculation to be safe */
    ldr w22, [x19, #0x50]       /* ADRP instruction */
    ldr w23, [x19, #0x54]       /* ADD instruction */

    /* Decode ADRP: immhi=bits[23:5], immlo=bits[30:29] */
    ubfx w24, w22, #5, #19      /* immhi */
    ubfx w25, w22, #29, #2      /* immlo */
    orr w24, w25, w24, lsl #2   /* 21-bit imm = immhi:immlo */
    /* Sign-extend 21 bits to 64 */
    sbfx x24, x24, #0, #21
    lsl x24, x24, #12           /* page offset */

    /* ADRP PC page */
    add x25, x19, #0x50
    and x25, x25, #~0xFFF
    add x24, x24, x25           /* x24 = target page */

    /* Decode ADD imm12 */
    ubfx w25, w23, #10, #12     /* imm12 */
    add x24, x24, x25           /* x24 = table base (no shift for MON table) */

    /* table[5] at +20 bytes */
    add x21, x24, #20

    /* set_memory_rw for table page */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    ldr w22, [x21]              /* old table[5] */
    mov w23, #6                  /* QDF_MONITOR_MODE */
    str w23, [x21]
    dc cvau, x21
    dsb ish

    ldr w25, [x21]              /* verify */

    adrp x0, fmt_p2
    add x0, x0, :lo12:fmt_p2
    mov x1, x21
    mov w2, w22
    mov w3, w25
    bl printk

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
