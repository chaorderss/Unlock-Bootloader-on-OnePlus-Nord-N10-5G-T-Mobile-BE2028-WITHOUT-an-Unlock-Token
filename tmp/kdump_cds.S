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
sym_cds_get:  .asciz "cds_get_context"
sym_cds_set:  .asciz "cds_set_context"
fmt_func:     .asciz "DCDS: %s @ %px\n"
fmt_code:     .asciz "DCDS: +0x%03lx: %08x %08x %08x %08x\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    // Find cds_get_context
    adrp x0, sym_cds_get
    add x0, x0, :lo12:sym_cds_get
    bl kallsyms_lookup_name
    mov x19, x0

    // Print address
    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    adrp x1, sym_cds_get
    add x1, x1, :lo12:sym_cds_get
    mov x2, x19
    bl printk

    // Dump 256 bytes of cds_get_context code
    cbz x19, .Lnext
    mov x20, #0

.Lloop1:
    cmp x20, #256
    b.ge .Lnext

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

.Lnext:
    // Find and dump cds_set_context
    adrp x0, sym_cds_set
    add x0, x0, :lo12:sym_cds_set
    bl kallsyms_lookup_name
    mov x19, x0

    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    adrp x1, sym_cds_set
    add x1, x1, :lo12:sym_cds_set
    mov x2, x19
    bl printk

    cbz x19, .Ldone
    mov x20, #0

.Lloop2:
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
    b .Lloop2

.Ldone:
    mov x0, #-1
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
