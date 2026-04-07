/*
 * kdump_vs.S - Dump send_vdev_start_cmd_tlv function
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
sym_func:   .asciz "send_vdev_start_cmd_tlv"
fmt_addr:   .asciz "kvs: func=%px\n"
fmt_hex:    .asciz "kvs: +%03x: %08x %08x %08x %08x\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    adrp x0, sym_func
    add x0, x0, :lo12:sym_func
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lret

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    bl printk

    /* Dump 768 bytes - this is a big function */
    mov x20, #0
.Ldump:
    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov x1, x20
    ldr w2, [x19, x20]
    add x21, x20, #4
    ldr w3, [x19, x21]
    add x21, x20, #8
    ldr w4, [x19, x21]
    add x21, x20, #12
    ldr w5, [x19, x21]
    bl printk
    add x20, x20, #16
    cmp x20, #768
    b.lt .Ldump

.Lret:
    mov w0, #-1
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
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
