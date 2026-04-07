/*
 * kdump_cfg.S - Dump cfg80211_change_iface function bytes
 * Build: as -o kdump_cfg.o kdump_cfg.S && ld -r -o kdump_cfg.ko kdump_cfg.o
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
sym_change:     .asciz "cfg80211_change_iface"
sym_can:        .asciz "cfg80211_can_change_interface"

fmt_addr:       .asciz "kcfg: %s @ %px\n"
fmt_hex:        .asciz "kcfg: +%03x: %08x %08x %08x %08x\n"
fmt_done:       .asciz "kcfg: done\n"
fmt_err:        .asciz "kcfg: sym not found\n"

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

    /* Dump cfg80211_change_iface - 512 bytes */
    adrp x0, sym_change
    add x0, x0, :lo12:sym_change
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    adrp x1, sym_change
    add x1, x1, :lo12:sym_change
    mov x2, x19
    bl printk

    /* Dump 512 bytes = 128 words */
    mov x20, x19            /* ptr */
    mov w21, #0              /* offset */
.Ldump1:
    cmp w21, #512
    b.ge .Ldump2_start

    ldr w22, [x20]
    ldr w23, [x20, #4]
    ldr w24, [x20, #8]
    ldr w25, [x20, #12]

    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov w1, w21
    mov w2, w22
    mov w3, w23
    mov w4, w24
    mov w5, w25
    bl printk

    add x20, x20, #16
    add w21, w21, #16
    b .Ldump1

.Ldump2_start:
    /* Also dump cfg80211_can_change_interface - 256 bytes */
    adrp x0, sym_can
    add x0, x0, :lo12:sym_can
    bl kallsyms_lookup_name
    cbz x0, .Ldone
    mov x19, x0

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    adrp x1, sym_can
    add x1, x1, :lo12:sym_can
    mov x2, x19
    bl printk

    mov x20, x19
    mov w21, #0
.Ldump2:
    cmp w21, #256
    b.ge .Ldone

    ldr w22, [x20]
    ldr w23, [x20, #4]
    ldr w24, [x20, #8]
    ldr w25, [x20, #12]

    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov w1, w21
    mov w2, w22
    mov w3, w23
    mov w4, w24
    mov w5, w25
    bl printk

    add x20, x20, #16
    add w21, w21, #16
    b .Ldump2

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #-1
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
