/* kdump_wma.S - Dump wma_set_channel and wma_vdev_start to understand params */

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
sym_wsc:    .asciz "wma_set_channel"
sym_wvs:    .asciz "wma_vdev_start"
fmt_d:      .asciz "KWMA: %s@%px:\n"
fmt_w:      .asciz "KWMA:  +%03x: %08x %08x %08x %08x\n"
name_wsc:   .asciz "wma_set_channel"
name_wvs:   .asciz "wma_vdev_start"

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

    /* Dump wma_set_channel (256 bytes) */
    adrp x0, sym_wsc
    add x0, x0, :lo12:sym_wsc
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone

    adrp x0, fmt_d
    add x0, x0, :lo12:fmt_d
    adrp x1, name_wsc
    add x1, x1, :lo12:name_wsc
    mov x2, x19
    bl printk

    mov x20, #0       /* offset */
.Lloop1:
    cmp x20, #256
    b.ge .Lnext

    adrp x0, fmt_w
    add x0, x0, :lo12:fmt_w
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
    b .Lloop1

.Lnext:
    /* Dump wma_vdev_start (256 bytes) */
    adrp x0, sym_wvs
    add x0, x0, :lo12:sym_wvs
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone

    adrp x0, fmt_d
    add x0, x0, :lo12:fmt_d
    adrp x1, name_wvs
    add x1, x1, :lo12:name_wvs
    mov x2, x19
    bl printk

    mov x20, #0
.Lloop2:
    cmp x20, #256
    b.ge .Ldone

    adrp x0, fmt_w
    add x0, x0, :lo12:fmt_w
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
    b .Lloop2

.Ldone:
    mov x0, #-1
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
