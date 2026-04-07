/* kdump_conparam.S - Dump hdd_get_conparam to find what it reads */

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
sym_func:   .asciz "hdd_get_conparam"
sym_setmon: .asciz "wlan_hdd_set_mon_chan"
fmt_dump:   .asciz "KDCP: func@%px: %08x %08x %08x %08x\n"
fmt_ret:    .asciz "KDCP: hdd_get_conparam() returned %d\n"
fmt_setmon: .asciz "KDCP: setmon@%px: %08x %08x %08x %08x %08x %08x %08x %08x\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Dump hdd_get_conparam */
    adrp x0, sym_func
    add x0, x0, :lo12:sym_func
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone

    /* Dump 16 bytes */
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov x1, x19
    ldr w2, [x19]
    ldr w3, [x19, #4]
    ldr w4, [x19, #8]
    ldr w5, [x19, #12]
    bl printk

    /* Call hdd_get_conparam */
    blr x19
    mov w20, w0

    adrp x0, fmt_ret
    add x0, x0, :lo12:fmt_ret
    mov w1, w20
    bl printk

    /* Dump wlan_hdd_set_mon_chan first 32 bytes */
    adrp x0, sym_setmon
    add x0, x0, :lo12:sym_setmon
    bl kallsyms_lookup_name
    mov x21, x0
    cbz x0, .Ldone

    adrp x0, fmt_setmon
    add x0, x0, :lo12:fmt_setmon
    mov x1, x21
    ldr w2, [x21]
    ldr w3, [x21, #4]
    ldr w4, [x21, #8]
    ldr w5, [x21, #12]
    ldr w6, [x21, #16]
    ldr w7, [x21, #20]
    /* pass remaining on stack */
    ldr w8, [x21, #24]
    ldr w9, [x21, #28]
    stp x8, x9, [sp, #-16]!
    bl printk
    add sp, sp, #16

.Ldone:
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
