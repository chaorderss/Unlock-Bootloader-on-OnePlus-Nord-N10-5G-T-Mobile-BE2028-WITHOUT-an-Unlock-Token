/*
 * kmon5b.S - Monitor mode enabler (FIXED v2)
 *
 * FIX: NL80211_IFTYPE_MONITOR = 6 (not 5!)
 *   1. Bitmask: 0x187 → 0x1C7 (add bit 6, not bit 5)
 *   2. Lookup table[6] = 4 (not table[5])
 *
 * FIX: Return -1 to avoid staying loaded (minimal module crashes when resident)
 * FIX: No stack slot corruption
 *
 * Build: as -o kmon5b.o kmon5b.S && ld -r -o kmon5b.ko kmon5b.o
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
sym_conv:       .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
sym_rwx:        .asciz "set_memory_rw"

fmt_info:       .asciz "kmon5: conv @ %px\n"
fmt_dump:       .asciz "kmon5: +%02x: %08x %08x %08x %08x\n"
fmt_p1:         .asciz "kmon5: bitmask: was=0x%08x now=0x%08x\n"
fmt_p2:         .asciz "kmon5: table @ %px [6]: was=%d now=%d\n"
fmt_err:        .asciz "kmon5: sym not found\n"
fmt_done:       .asciz "kmon5: DONE\n"

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

    /* Resolve convert_nl_iftype */
    adrp x0, sym_conv
    add x0, x0, :lo12:sym_conv
    bl kallsyms_lookup_name
    mov x19, x0
    cbnz x0, 1f
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    b .Lfail
1:
    /* Resolve set_memory_rw */
    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x20, x0

    /* Print function address */
    adrp x0, fmt_info
    add x0, x0, :lo12:fmt_info
    mov x1, x19
    bl printk

    /* Dump first 48 bytes */
    mov w21, #0
.Ldump:
    cmp w21, #48
    b.ge .Lpatch1

    add x22, x19, x21
    ldr w23, [x22]
    ldr w24, [x22, #4]
    ldr w25, [x22, #8]
    ldr w26, [x22, #12]

    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w21
    mov w2, w23
    mov w3, w24
    mov w4, w25
    mov w5, w26
    bl printk

    add w21, w21, #16
    b .Ldump

/* ========= PATCH 1: bitmask at func+0x10 ========= */
.Lpatch1:
    cbz x20, .Lfail              /* need set_memory_rw */

    add x21, x19, #0x10          /* addr of bitmask insn */
    ldr w22, [x21]               /* current instruction */

    /* Make page writable */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Encode MOVZ W9, #0x1C7 = 0x528038e9 */
    mov w23, #0x38e9
    movk w23, #0x5280, lsl #16
    str w23, [x21]
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    adrp x0, fmt_p1
    add x0, x0, :lo12:fmt_p1
    mov w1, w22                  /* old */
    mov w2, w23                  /* new */
    bl printk

/* ========= PATCH 2: table[6] at ADRP+ADD decoded address ========= */
.Lpatch2:
    /* Decode ADRP at func+0x1c */
    ldr w22, [x19, #0x1c]       /* ADRP insn */

    /* immhi = bits[23:5], immlo = bits[30:29] */
    ubfx w23, w22, #5, #19
    ubfx w24, w22, #29, #2
    orr w23, w24, w23, lsl #2   /* 21-bit value */
    sbfx x23, x23, #0, #21     /* sign-extend */
    lsl x23, x23, #12

    /* ADRP PC page = (func+0x1c) & ~0xFFF */
    add x24, x19, #0x1c
    and x24, x24, #~0xFFF
    add x23, x23, x24           /* x23 = ADRP target page */

    /* Decode ADD at func+0x20 */
    ldr w22, [x19, #0x20]
    ubfx w24, w22, #10, #12     /* imm12 */
    tbnz w22, #22, .Lp2_sh
    add x23, x23, x24
    b .Lp2_go
.Lp2_sh:
    add x23, x23, x24, lsl #12
.Lp2_go:
    /* x23 = table base. table[6] at offset 6*4=24 */
    add x24, x23, #24
    ldr w25, [x24]              /* old table[6] */

    /* Make page writable */
    mov x0, x24
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Write 4 = QDF_MONITOR_MODE */
    mov w26, #4
    str w26, [x24]
    dc cvau, x24
    dsb ish

    ldr w26, [x24]              /* verify */
    adrp x0, fmt_p2
    add x0, x0, :lo12:fmt_p2
    mov x1, x23                 /* table base */
    mov w2, w25                 /* old val */
    mov w3, w26                 /* new val */
    bl printk

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk

.Lfail:
    mov w0, #-1                  /* ALWAYS fail to unload - patches persist in wlan module */

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
