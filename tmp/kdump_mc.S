/*
 * kdump_mc.S - Dump wlan_hdd_set_mon_chan function
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
sym1:   .asciz "wlan_hdd_set_mon_chan"
sym2:   .asciz "hdd_set_mon_rx_cb"
fmt_addr:   .asciz "kmc: %s=%px\n"
fmt_hex:    .asciz "kmc: %s+%03x: %08x %08x %08x %08x\n"

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

    /* Dump wlan_hdd_set_mon_chan */
    adrp x0, sym1
    add x0, x0, :lo12:sym1
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lskip1

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    adrp x1, sym1
    add x1, x1, :lo12:sym1
    mov x2, x19
    bl printk

    /* Dump 384 bytes */
    mov x20, #0
.Ldump1:
    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    adrp x1, sym1
    add x1, x1, :lo12:sym1
    mov x2, x20
    ldr w3, [x19, x20]
    add x21, x20, #4
    ldr w4, [x19, x21]
    add x21, x20, #8
    ldr w5, [x19, x21]
    add x21, x20, #12
    ldr w6, [x19, x21]
    bl printk
    add x20, x20, #16
    cmp x20, #384
    b.lt .Ldump1

.Lskip1:
    /* Dump hdd_set_mon_rx_cb */
    adrp x0, sym2
    add x0, x0, :lo12:sym2
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lret

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    adrp x1, sym2
    add x1, x1, :lo12:sym2
    mov x2, x19
    bl printk

    mov x20, #0
.Ldump2:
    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    adrp x1, sym2
    add x1, x1, :lo12:sym2
    mov x2, x20
    ldr w3, [x19, x20]
    add x21, x20, #4
    ldr w4, [x19, x21]
    add x21, x20, #8
    ldr w5, [x19, x21]
    add x21, x20, #12
    ldr w6, [x19, x21]
    bl printk
    add x20, x20, #16
    cmp x20, #256
    b.lt .Ldump2

.Lret:
    mov w0, #-1
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
