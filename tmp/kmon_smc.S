/*
 * kmon_smc.S - Patch wlan_hdd_cfg80211_set_mon_ch to look for MONITOR adapter
 *
 * The function at +0x8c has: ORR W1, WZR, #6 (QDF_IBSS_MODE)
 * It should be: ORR W1, WZR, #4 (QDF_MONITOR_MODE)
 *
 * Old instruction at +0x8c: 0x321f07e1 (ORR W1, WZR, #6)
 * New instruction at +0x8c: 0x321e03e1 (ORR W1, WZR, #4)
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
sym_func:   .asciz "wlan_hdd_cfg80211_set_mon_ch"
sym_rw:     .asciz "set_memory_rw"

fmt_addr:   .asciz "ksmc: func=%px\n"
fmt_old:    .asciz "ksmc: +0x8c: 0x%08x -> 0x321e03e1 (ORR W1,WZR,#4)\n"
fmt_done:   .asciz "ksmc: set_mon_ch patched to find MONITOR adapter\n"
fmt_err:    .asciz "ksmc: error\n"
fmt_mismatch: .asciz "ksmc: unexpected instruction at +0x8c: 0x%08x\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    /* Resolve function */
    adrp x0, sym_func
    add x0, x0, :lo12:sym_func
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

    /* Read current instruction at +0x8c */
    add x21, x19, #0x8c
    ldr w22, [x21]

    adrp x0, fmt_old
    add x0, x0, :lo12:fmt_old
    mov w1, w22
    bl printk

    /* Verify it's the expected instruction */
    mov w23, #0x07e1
    movk w23, #0x321f, lsl #16
    cmp w22, w23
    b.ne .Lmismatch

    /* Make page writable */
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    /* Write new instruction: ORR W1, WZR, #4 = 0x321e03e1 */
    mov w23, #0x03e1
    movk w23, #0x321e, lsl #16
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

.Lmismatch:
    adrp x0, fmt_mismatch
    add x0, x0, :lo12:fmt_mismatch
    mov w1, w22
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
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
