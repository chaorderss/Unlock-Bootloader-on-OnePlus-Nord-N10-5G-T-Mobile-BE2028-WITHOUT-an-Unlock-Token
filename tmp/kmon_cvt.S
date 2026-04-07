/*
 * kmon_cvt.S - Patch cds_get_vdev_types for MONITOR mode support
 *
 * Two patches needed:
 * 1. Jump table byte[4] → set to 0x1A (offset for +0x098 MONITOR handler)
 *    Handler at +0x098: ORR W8, WZR, #4 (WMI_VDEV_TYPE_MONITOR)
 *
 * 2. Branch at +0x09C: change from B +0xC8 to B +0xCC
 *    +0xC8 has MOVZ W8,#5 which overwrites our type=4
 *    +0xCC is the clean epilogue: MOV W0,WZR; STR W8,[X1]; RET
 *    Old: 0x1400000b (offset 11 words=44 bytes → +0xC8)
 *    New: 0x1400000c (offset 12 words=48 bytes → +0xCC)
 *
 * Jump table address: decode ADRP at func+0x14 + ADD at func+0x1C
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
sym_cvt:    .asciz "cds_get_vdev_types"
sym_rw:     .asciz "set_memory_rw"

fmt_addr:   .asciz "kcvt: func=%px\n"
fmt_jt:     .asciz "kcvt: jump_table=%px byte[4]=0x%02x -> 0x1a\n"
fmt_br:     .asciz "kcvt: +0x9c: 0x%08x -> 0x1400000c\n"
fmt_done:   .asciz "kcvt: cds_get_vdev_types patched for MONITOR\n"
fmt_err:    .asciz "kcvt: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]

    /* Resolve cds_get_vdev_types */
    adrp x0, sym_cvt
    add x0, x0, :lo12:sym_cvt
    bl kallsyms_lookup_name
    mov x19, x0       /* x19 = func */
    cbz x0, .Lerr

    /* Resolve set_memory_rw */
    adrp x0, sym_rw
    add x0, x0, :lo12:sym_rw
    bl kallsyms_lookup_name
    mov x20, x0       /* x20 = set_memory_rw */
    cbz x0, .Lerr

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    bl printk

    /* === Patch 1: Decode ADRP+ADD to find jump table === */
    /* ADRP at func+0x14, ADD at func+0x1C */
    ldr w21, [x19, #0x14]    /* ADRP instruction */
    ldr w22, [x19, #0x1C]    /* ADD instruction */

    /* Decode ADRP: immhi[23:5], immlo[30:29] */
    /* PC at func+0x14 → page = (func+0x14) & ~0xFFF */
    add x23, x19, #0x14      /* PC of ADRP */
    and x24, x23, #~0xFFF    /* PC page */

    /* Extract immhi (bits 23:5) and immlo (bits 30:29) */
    ubfx x25, x21, #5, #19   /* immhi = bits[23:5] */
    ubfx x26, x21, #29, #2   /* immlo = bits[30:29] */
    orr x25, x26, x25, lsl #2 /* imm21 = immhi:immlo */

    /* Sign-extend 21-bit to 64-bit */
    sbfx x25, x25, #0, #21

    /* ADRP result = PC_page + imm21 * 4096 */
    add x24, x24, x25, lsl #12  /* page result */

    /* Decode ADD #imm12 from second instruction */
    ubfx x26, x22, #10, #12  /* imm12 = bits[21:10] */

    /* Jump table address = page + imm12 */
    add x25, x24, x26        /* x25 = jump table base */

    /* Read byte[4] (device_mode=MONITOR) */
    ldrb w26, [x25, #4]

    adrp x0, fmt_jt
    add x0, x0, :lo12:fmt_jt
    mov x1, x25
    mov w2, w26
    bl printk

    /* Make jump table page writable */
    mov x0, x25
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Write new byte: 0x1A (=26, offset for func+0x098 MONITOR handler) */
    mov w27, #0x1A
    strb w27, [x25, #4]

    /* Cache clean for jump table */
    add x0, x25, #4
    dc cvau, x0
    dsb ish

    /* === Patch 2: Fix branch at func+0x9C === */
    add x21, x19, #0x9C      /* branch instruction address */
    ldr w22, [x21]            /* current instruction */

    adrp x0, fmt_br
    add x0, x0, :lo12:fmt_br
    mov w1, w22
    bl printk

    /* Make code page writable */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Write new branch: B +0xCC instead of B +0xC8 */
    /* New instruction: 0x1400000c */
    mov w23, #0x000c
    movk w23, #0x1400, lsl #16
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
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
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
