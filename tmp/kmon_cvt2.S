/*
 * kmon_cvt2.S - Fix cds_get_vdev_types patches
 *
 * Corrected offsets:
 *   +0x9C: ORR W8, WZR, #4 (0x321e03e8) - MUST REMAIN, was wrongly overwritten
 *   +0xA0: B instruction → patch this one to jump to epilogue +0xCC
 *
 * Jump table byte[4] should be 0x1B (27) → target = base(+0x30) + 27*4 = +0x9C
 *
 * Branch at +0xA0:
 *   From +0xA0 to +0xC8 = 0x28 bytes = 10 words → old: 0x1400000a
 *   From +0xA0 to +0xCC = 0x2C bytes = 11 words → new: 0x1400000b
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

fmt_addr:   .asciz "kcvt2: func=%px\n"
fmt_dump:   .asciz "kcvt2: +0x98=%08x +0x9c=%08x +0xa0=%08x +0xa4=%08x\n"
fmt_jt:     .asciz "kcvt2: jt byte[4]=0x%02x -> 0x1b\n"
fmt_fix9c:  .asciz "kcvt2: restored +0x9c: 0x%08x -> 0x321e03e8\n"
fmt_a0:     .asciz "kcvt2: patched +0xa0: 0x%08x -> 0x1400000b\n"
fmt_done:   .asciz "kcvt2: cds_get_vdev_types MONITOR patch complete\n"
fmt_err:    .asciz "kcvt2: error\n"

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

    /* Dump instructions around the MONITOR handler */
    ldr w21, [x19, #0x98]
    ldr w22, [x19, #0x9c]
    ldr w23, [x19, #0xa0]
    ldr w24, [x19, #0xa4]

    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w21
    mov w2, w22
    mov w3, w23
    mov w4, w24
    bl printk

    /* Decode ADRP+ADD for jump table address */
    ldr w21, [x19, #0x14]    /* ADRP instruction */
    ldr w22, [x19, #0x1C]    /* ADD instruction */

    add x23, x19, #0x14
    and x24, x23, #~0xFFF

    ubfx x25, x21, #5, #19
    ubfx x26, x21, #29, #2
    orr x25, x26, x25, lsl #2
    sbfx x25, x25, #0, #21
    add x24, x24, x25, lsl #12

    ubfx x26, x22, #10, #12
    add x25, x24, x26        /* x25 = jump table base */

    /* Print current jump table byte[4] */
    ldrb w26, [x25, #4]
    adrp x0, fmt_jt
    add x0, x0, :lo12:fmt_jt
    mov w1, w26
    bl printk

    /* Make jump table page writable and fix byte[4] to 0x1B */
    mov x0, x25
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    mov w27, #0x1B
    strb w27, [x25, #4]
    add x0, x25, #4
    dc cvau, x0
    dsb ish

    /* Make code page writable for func+0x9C..+0xA0 */
    add x21, x19, #0x9C
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Restore +0x9C to ORR W8, WZR, #4 (0x321e03e8) */
    ldr w22, [x21]          /* current value at +0x9C */
    adrp x0, fmt_fix9c
    add x0, x0, :lo12:fmt_fix9c
    mov w1, w22
    bl printk

    mov w23, #0x03e8
    movk w23, #0x321e, lsl #16
    str w23, [x21]
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    /* Patch +0xA0: B from +0xC8 to +0xCC */
    add x21, x19, #0xA0
    ldr w22, [x21]          /* current value at +0xA0 */
    adrp x0, fmt_a0
    add x0, x0, :lo12:fmt_a0
    mov w1, w22
    bl printk

    /* New instruction: B +0x2C (11 words forward → +0xCC) = 0x1400000b */
    mov w23, #0x000b
    movk w23, #0x1400, lsl #16
    str w23, [x21]
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
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
