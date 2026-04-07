// kmon_ci.S - Patch change_iface type bitmask to include MONITOR (bit 6)
// At change_iface+0x298: MOVZ W9, #0x106 -> MOVZ W9, #0x146

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

.section .plt,"ax"
.space 8
.section .init.plt,"ax"
.space 8
.section .text.ftrace_trampoline,"ax"
.space 8

.section .rodata, "a"
sym_ci:     .asciz "wlan_hdd_cfg80211_change_iface"
sym_rw:     .asciz "set_memory_rw"
fmt_patch:  .asciz "kci: change_iface+0x298: 0x%08x -> 0x528028c9\n"
fmt_err:    .asciz "kci: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    adrp x0, sym_ci
    add x0, x0, :lo12:sym_ci
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    adrp x0, sym_rw
    add x0, x0, :lo12:sym_rw
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    // Patch at +0x298
    add x21, x19, #0x298
    ldr w22, [x21]

    // Make page writable
    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20

    // Write MOVZ W9, #0x146 = 0x528028C9
    mov w0, #0x28C9
    movk w0, #0x5280, lsl #16
    str w0, [x21]
    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    adrp x0, fmt_patch
    add x0, x0, :lo12:fmt_patch
    mov w1, w22
    bl printk
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov x0, #-1
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
