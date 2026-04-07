/*
 * kmon5.S - Monitor mode enabler (FIXED)
 *
 * Previous kmon2 had off-by-one: patched bit 5 + table[5] instead of bit 6 + table[6]
 * NL80211_IFTYPE_MONITOR = 6, so we need:
 *   1. Bitmask: 0x187 → 0x1C7 (add bit 6)
 *   2. Lookup table[6] = 4 (QDF_MONITOR_MODE)
 *
 * cfg80211 already has interface_modes with BIT(6) and combo[9] with MONITOR.
 * The only blocker is the driver's convert_nl_iftype function.
 *
 * Build: as -o kmon5.o kmon5.S && ld -r -o kmon5.ko kmon5.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kmon5"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kmon5"
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

fmt_info:       .asciz "kmon5: %s @ %px\n"
fmt_p1ok:       .asciz "kmon5: PATCH1 bitmask 0x%03x -> 0x%03x OK\n"
fmt_p1skip:     .asciz "kmon5: PATCH1 already 0x1C7, skip\n"
fmt_p1bad:      .asciz "kmon5: PATCH1 unexpected insn 0x%08x at +0x10\n"
fmt_p2ok:       .asciz "kmon5: PATCH2 table[6]=%d -> 4 OK\n"
fmt_p2info:     .asciz "kmon5: table @ %px, [6]=%d\n"
fmt_rwx:        .asciz "kmon5: set_memory_rw(%px, 1) = %d\n"
fmt_err:        .asciz "kmon5: ERROR sym not found\n"
fmt_done:       .asciz "kmon5: ALL PATCHES DONE\n"
fmt_dump:       .asciz "kmon5: func+%02x: %08x %08x %08x %08x\n"

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

    /* Resolve wlan_hdd_convert_nl_iftype_to_hdd_type */
    adrp x0, sym_conv
    add x0, x0, :lo12:sym_conv
    bl kallsyms_lookup_name
    mov x19, x0                  /* x19 = convert_nl_iftype */
    cbnz x0, 1f
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    b .Lfail
1:
    adrp x0, fmt_info
    add x0, x0, :lo12:fmt_info
    adrp x1, sym_conv
    add x1, x1, :lo12:sym_conv
    mov x2, x19
    bl printk

    /* Resolve set_memory_rw */
    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x20, x0                  /* x20 = set_memory_rw */

    /* Dump first 64 bytes of function for debugging */
    mov w21, #0
.Ldump:
    cmp w21, #64
    b.ge .Lpatch1

    add x0, x19, x21
    ldr w22, [x0]
    ldr w23, [x0, #4]
    ldr w24, [x0, #8]
    ldr w25, [x0, #12]

    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w21
    mov w2, w22
    mov w3, w23
    mov w4, w24
    mov w5, w25
    bl printk

    add w21, w21, #16
    b .Ldump

    /* ========= PATCH 1: Fix bitmask 0x187 → 0x1C7 ========= */
    /* At convert_nl_iftype + 0x10: MOV W9, #imm16 */
    /* 0x528030e9 = MOVZ W9, #0x187 → 0x528038e9 = MOVZ W9, #0x1C7 */
.Lpatch1:
    add x23, x19, #0x10
    ldr w24, [x23]

    /* Check for original: 0x528030e9 */
    mov w25, #0x30e9
    movk w25, #0x5280, lsl #16
    cmp w24, w25
    b.eq .Lpatch1_do

    /* Check for already-patched 0x528038e9 */
    mov w25, #0x38e9
    movk w25, #0x5280, lsl #16
    cmp w24, w25
    b.eq .Lpatch1_skip

    /* Check for wrong kmon2 patch 0x528034e9 → fix it */
    mov w25, #0x34e9
    movk w25, #0x5280, lsl #16
    cmp w24, w25
    b.eq .Lpatch1_do

    /* Unknown instruction */
    adrp x0, fmt_p1bad
    add x0, x0, :lo12:fmt_p1bad
    mov w1, w24
    bl printk
    b .Lpatch2

.Lpatch1_skip:
    adrp x0, fmt_p1skip
    add x0, x0, :lo12:fmt_p1skip
    bl printk
    b .Lpatch2

.Lpatch1_do:
    /* Make page writable */
    cbz x20, .Lpatch2
    mov x0, x23
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20                      /* set_memory_rw */

    str w0, [sp, #88]            /* save retval */
    adrp x0, fmt_rwx
    add x0, x0, :lo12:fmt_rwx
    mov x1, x23
    ldr w2, [sp, #88]
    bl printk

    /* Write the correct bitmask: 0x1C7 = 0x187 | 0x40 (add BIT(6) for MONITOR) */
    mov w25, #0x38e9
    movk w25, #0x5280, lsl #16  /* MOVZ W9, #0x1C7 */
    str w25, [x23]
    dc cvau, x23
    dsb ish
    ic ivau, x23
    dsb ish
    isb

    /* Extract old and new bitmask values for logging */
    /* Old was in w24 (original instruction), extract imm16 */
    ubfx w26, w24, #5, #16      /* old imm16 */
    adrp x0, fmt_p1ok
    add x0, x0, :lo12:fmt_p1ok
    mov w1, w26                  /* old mask */
    mov w2, #0x1C7               /* new mask */
    bl printk

    /* ========= PATCH 2: Fix lookup table[6] = 4 ========= */
.Lpatch2:
    /* Decode ADRP at convert_nl_iftype + 0x1c to find table base */
    add x23, x19, #0x1c         /* ADRP instruction addr */
    ldr w24, [x23]              /* ADRP instruction word */

    /* Extract ADRP: immhi = bits[23:5], immlo = bits[30:29] */
    ubfx w25, w24, #5, #19      /* immhi (19 bits) */
    ubfx w26, w24, #29, #2      /* immlo (2 bits) */
    orr w25, w26, w25, lsl #2   /* full 21-bit imm = immhi:immlo */
    sbfx x25, x25, #0, #21      /* sign-extend */
    lsl x25, x25, #12           /* << 12 for page offset */
    and x26, x23, #~0xFFF       /* ADRP instruction page */
    add x26, x26, x25           /* x26 = target page */

    /* Get ADD instruction at +0x20 */
    ldr w24, [x19, #0x20]       /* ADD Xd, Xn, #imm12 */
    ubfx w25, w24, #10, #12     /* imm12 */
    tbnz w24, #22, .Lp2_shifted
    add x26, x26, x25           /* x26 = table base (no shift) */
    b .Lp2_calc
.Lp2_shifted:
    add x26, x26, x25, lsl #12
.Lp2_calc:
    /* x26 = table base. table[6] is at offset 6*4 = 24 */
    add x27, x26, #24           /* addr of table[6] */

    ldr w28, [x27]              /* current value */
    adrp x0, fmt_p2info
    add x0, x0, :lo12:fmt_p2info
    mov x1, x26                  /* table base */
    mov w2, w28                  /* current table[6] */
    bl printk

    /* Make page writable */
    cbz x20, .Ldone
    mov x0, x27
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Write 4 (QDF_MONITOR_MODE) to table[6] */
    mov w25, #4
    str w25, [x27]
    dc cvau, x27
    dsb ish

    ldr w28, [x27]              /* verify */
    adrp x0, fmt_p2ok
    add x0, x0, :lo12:fmt_p2ok
    mov w1, w28
    bl printk

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0                   /* Stay loaded */
    b .Lret

.Lfail:
    mov w0, #-1

.Lret:
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
