/*
 * kdump_start.S - Dump hdd_start_adapter function (512 bytes)
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
sym_start:  .asciz "hdd_start_adapter"
fmt_func:   .asciz "kds: start_adapter +%03x: %08x %08x %08x %08x\n"
fmt_err:    .asciz "kds: error\n"

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

    adrp x0, sym_start
    add x0, x0, :lo12:sym_start
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Dump 512 bytes */
    mov w20, #0

.Ldump:
    cmp w20, #512
    b.ge .Ldone

    add x21, x19, x20
    ldr w22, [x21]
    ldr w23, [x21, #4]
    ldr w24, [x21, #8]
    ldr w25, [x21, #12]

    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    mov w1, w20
    mov w2, w22
    mov w3, w23
    mov w4, w24
    mov w5, w25
    bl printk

    add w20, w20, #16
    b .Ldump

.Ldone:
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
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
