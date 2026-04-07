/*
 * kmon.S - Patch wlan driver to enable monitor mode
 *
 * Patches wlan_hdd_convert_nl_iftype_to_hdd_type:
 *   Change bitmask from 0x187 to 0x1A7 to allow NL80211_IFTYPE_MONITOR (6)
 *   0x187 = 0b110000111 (IBSS,managed,AP,P2P)
 *   0x1A7 = 0b110100111 (adds MONITOR at bit 5)
 *
 * Also dumps the lookup table entry for monitor mode.
 *
 * Build: as -o kmon.o kmon.S && ld -r -o kmon.ko kmon.o
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

fmt_found:  .asciz "kmon: func @ %px\n"
fmt_insn:   .asciz "kmon: +010 before: %08x\n"
fmt_after:  .asciz "kmon: +010 after:  %08x\n"
fmt_table:  .asciz "kmon: lookup table[5] (monitor) = %d\n"
fmt_ok:     .asciz "kmon: monitor mode ENABLED\n"
fmt_err:    .asciz "kmon: ERROR - symbol not found or bad insn\n"
fmt_already:.asciz "kmon: already patched\n"
fmt_rw:     .asciz "kmon: set_memory_rw @ %px, page=%px\n"

.equ ORIG_INSN,   0x528030e9   /* movz w9, #0x187 */
.equ PATCHED_INSN, 0x528034e9  /* movz w9, #0x1A7 */
.equ PATCH_OFFSET, 0x10

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

    /* Resolve function */
    adrp x0, str_func
    add x0, x0, :lo12:str_func
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0                /* x19 = function addr */

    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov x1, x19
    bl printk

    /* Resolve set_memory_rw */
    adrp x0, str_setmemrw
    add x0, x0, :lo12:str_setmemrw
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0                /* x20 = set_memory_rw */

    /* Read current instruction at +0x10 */
    add x21, x19, #PATCH_OFFSET
    ldr w22, [x21]             /* w22 = current insn */

    adrp x0, fmt_insn
    add x0, x0, :lo12:fmt_insn
    mov w1, w22
    bl printk

    /* Check if already patched */
    mov w23, #PATCHED_INSN & 0xffff
    movk w23, #PATCHED_INSN >> 16, lsl #16
    cmp w22, w23
    b.eq .Lalready

    /* Verify it's the expected original instruction */
    mov w24, #ORIG_INSN & 0xffff
    movk w24, #ORIG_INSN >> 16, lsl #16
    cmp w22, w24
    b.ne .Lerr

    /* Make page writable: set_memory_rw(page_addr, 1) */
    and x0, x21, #0xfffffffffffff000    /* page-align */
    mov x25, x0                         /* save page addr */

    adrp x0, fmt_rw
    add x0, x0, :lo12:fmt_rw
    mov x1, x20
    mov x2, x25
    bl printk

    mov x0, x25
    mov x1, #1
    blr x20                    /* set_memory_rw(page, 1) */

    /* Write patched instruction */
    mov w23, #PATCHED_INSN & 0xffff
    movk w23, #PATCHED_INSN >> 16, lsl #16
    str w23, [x21]

    /* Flush icache */
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    /* Verify */
    ldr w22, [x21]
    adrp x0, fmt_after
    add x0, x0, :lo12:fmt_after
    mov w1, w22
    bl printk

    /* Now dump lookup table entry for monitor mode (index 5) */
    /* Table is at func+0x50: adrp x9, ... ; add x9, x9, #0x1a8 ; ldr w0, [x9, w8, sxtw #2] */
    /* We need to decode the ADRP to find the table address */
    ldr w22, [x19, #0x50]      /* ADRP instruction */
    /* ADRP: immhi = [23:5], immlo = [30:29], page offset = immhi:immlo:zeros(12) */
    ubfx x23, x22, #5, #19     /* immhi */
    ubfx x24, x22, #29, #2     /* immlo */
    orr x23, x24, x23, lsl #2  /* immhi:immlo = full imm */
    /* Sign extend 21-bit */
    sbfx x23, x23, #0, #21
    /* Page of ADRP instruction */
    add x24, x19, #0x50
    and x24, x24, #0xfffffffffffff000
    add x24, x24, x23, lsl #12   /* table page */
    /* ADD offset from +0x54: add x9, x9, #0x1a8 */
    add x24, x24, #0x1a8         /* table base */
    /* Read table[5] for monitor mode (iftype 6, index 5) */
    ldr w22, [x24, #20]          /* 5 * 4 = 20 */

    adrp x0, fmt_table
    add x0, x0, :lo12:fmt_table
    mov w1, w22
    bl printk

    adrp x0, fmt_ok
    add x0, x0, :lo12:fmt_ok
    bl printk

    mov w0, #0
    b .Lret

.Lalready:
    adrp x0, fmt_already
    add x0, x0, :lo12:fmt_already
    bl printk
    mov w0, #0
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1

.Lret:
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
