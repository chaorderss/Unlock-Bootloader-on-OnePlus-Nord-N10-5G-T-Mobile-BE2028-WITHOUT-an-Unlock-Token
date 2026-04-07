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
sym_mon:    .asciz "hdd_mon_open"
sym_vs:     .asciz "wma_vdev_start"
sym_sc:     .asciz "wma_set_channel"
fmt_func:   .asciz "DWVS: %s @ %px\n"
fmt_code:   .asciz "DWVS: +0x%03lx: %08x %08x %08x %08x\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    // Dump hdd_mon_open (256 bytes)
    adrp x0, sym_mon
    add x0, x0, :lo12:sym_mon
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lnext1
    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    adrp x1, sym_mon
    add x1, x1, :lo12:sym_mon
    mov x2, x19
    bl printk
    mov x20, #0
.Lloop1:
    cmp x20, #256
    b.ge .Lnext1
    add x21, x19, x20
    ldr w2, [x21]
    ldr w3, [x21, #4]
    ldr w4, [x21, #8]
    ldr w5, [x21, #12]
    adrp x0, fmt_code
    add x0, x0, :lo12:fmt_code
    mov x1, x20
    bl printk
    add x20, x20, #16
    b .Lloop1

.Lnext1:
    // Dump wma_set_channel (512 bytes)
    adrp x0, sym_sc
    add x0, x0, :lo12:sym_sc
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lnext2
    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    adrp x1, sym_sc
    add x1, x1, :lo12:sym_sc
    mov x2, x19
    bl printk
    mov x20, #0
.Lloop2:
    cmp x20, #512
    b.ge .Lnext2
    add x21, x19, x20
    ldr w2, [x21]
    ldr w3, [x21, #4]
    ldr w4, [x21, #8]
    ldr w5, [x21, #12]
    adrp x0, fmt_code
    add x0, x0, :lo12:fmt_code
    mov x1, x20
    bl printk
    add x20, x20, #16
    b .Lloop2

.Lnext2:
    // Dump wma_vdev_start first 256 bytes
    adrp x0, sym_vs
    add x0, x0, :lo12:sym_vs
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone
    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    adrp x1, sym_vs
    add x1, x1, :lo12:sym_vs
    mov x2, x19
    bl printk
    mov x20, #0
.Lloop3:
    cmp x20, #256
    b.ge .Ldone
    add x21, x19, x20
    ldr w2, [x21]
    ldr w3, [x21, #4]
    ldr w4, [x21, #8]
    ldr w5, [x21, #12]
    adrp x0, fmt_code
    add x0, x0, :lo12:fmt_code
    mov x1, x20
    bl printk
    add x20, x20, #16
    b .Lloop3

.Ldone:
    mov x0, #-1
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
