/*
 * kmon2.S - Enable monitor mode in wlan driver
 *
 * Patches wlan_hdd_convert_nl_iftype_to_hdd_type:
 * 1. Bitmask: 0x187 → 0x1A7 (allow MONITOR iftype 6)
 * 2. Lookup table[5] → 4 (QDF_MONITOR_MODE = 4)
 *
 * Build: as -o kmon2.o kmon2.S && ld -r -o kmon2.ko kmon2.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kmon"
    .fill 51, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kmon"
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
str_func:       .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
str_setmemrw:   .asciz "set_memory_rw"

fmt_found:  .asciz "kmon2: func @ %px\n"
fmt_bitmask:.asciz "kmon2: bitmask patched: %08x -> %08x\n"
fmt_table:  .asciz "kmon2: table @ %px, table[5] was %d, now %d\n"
fmt_ok:     .asciz "kmon2: monitor mode ENABLED (bitmask + table patched)\n"
fmt_err:    .asciz "kmon2: ERROR\n"
fmt_already:.asciz "kmon2: already patched\n"

.equ ORIG_INSN,    0x528030e9   /* movz w9, #0x187 */
.equ PATCHED_INSN, 0x528034e9   /* movz w9, #0x1A7 */
.equ PATCH_OFFSET, 0x10
.equ QDF_MONITOR_MODE, 4

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
    adrp x0, str_func
    add x0, x0, :lo12:str_func
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0            /* x19 = function addr */

    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov x1, x19
    bl printk

    /* Resolve set_memory_rw */
    adrp x0, str_setmemrw
    add x0, x0, :lo12:str_setmemrw
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0            /* x20 = set_memory_rw */

    /* ===== PATCH 1: Bitmask at func+0x10 ===== */
    add x21, x19, #PATCH_OFFSET
    ldr w22, [x21]

    /* Check if already patched */
    mov w23, #PATCHED_INSN & 0xffff
    movk w23, #PATCHED_INSN >> 16, lsl #16
    cmp w22, w23
    b.eq .Lpatch2           /* Already patched, skip to table */

    /* Verify original instruction */
    mov w24, #ORIG_INSN & 0xffff
    movk w24, #ORIG_INSN >> 16, lsl #16
    cmp w22, w24
    b.ne .Lerr

    /* Make code page writable */
    and x0, x21, #0xfffffffffffff000
    mov x1, #1
    blr x20

    /* Write new bitmask instruction */
    mov w23, #PATCHED_INSN & 0xffff
    movk w23, #PATCHED_INSN >> 16, lsl #16
    str w23, [x21]
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    /* Verify patch */
    ldr w25, [x21]
    adrp x0, fmt_bitmask
    add x0, x0, :lo12:fmt_bitmask
    mov w1, w22             /* old value */
    mov w2, w25             /* new value */
    bl printk

    /* ===== PATCH 2: Lookup table[5] = QDF_MONITOR_MODE ===== */
.Lpatch2:
    /* Decode ADRP at func+0x50 */
    ldr w22, [x19, #0x50]  /* ADRP instruction */
    /* Extract immhi (bits 23:5) and immlo (bits 30:29) */
    ubfx w23, w22, #5, #19     /* immhi */
    ubfx w24, w22, #29, #2     /* immlo */
    orr w23, w24, w23, lsl #2  /* imm21 = immhi:immlo */
    /* Sign-extend 21-bit to 64-bit */
    sxtw x23, w23
    sbfx x23, x23, #0, #21

    /* Compute table base = page(PC_of_ADRP) + imm << 12 + add_offset */
    add x24, x19, #0x50
    and x24, x24, #0xfffffffffffff000   /* page of ADRP instruction */
    add x24, x24, x23, lsl #12          /* + page offset */
    /* ADD instruction at func+0x54 adds #0x1a8 */
    add x24, x24, #0x1a8                /* x24 = table base */

    /* Read old value at table[5] (offset 5*4=20) */
    ldr w25, [x24, #20]
    mov x26, x24            /* Save table base */

    /* Make table page writable */
    and x0, x24, #0xfffffffffffff000
    mov x1, #1
    blr x20

    /* Write QDF_MONITOR_MODE (4) to table[5] */
    mov w27, #QDF_MONITOR_MODE
    str w27, [x26, #20]
    add x28, x26, #20
    dc cvau, x28
    dsb ish

    /* Verify */
    ldr w28, [x26, #20]
    adrp x0, fmt_table
    add x0, x0, :lo12:fmt_table
    mov x1, x26
    mov w2, w25              /* old value */
    mov w3, w28              /* new value */
    bl printk

    /* Done */
    adrp x0, fmt_ok
    add x0, x0, :lo12:fmt_ok
    bl printk

    mov w0, #0
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
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
