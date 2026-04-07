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
sym_cds:    .asciz "cds_get_context"
fmt_ctx:    .asciz "CDS3: cds_get_context(0x%x) = %px\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    // Find cds_get_context
    adrp x0, sym_cds
    add x0, x0, :lo12:sym_cds
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone

    // Call with IDs 0x33 to 0x46 (the CORRECT module IDs)
    mov x20, #0x33

.Lloop:
    cmp x20, #0x47
    b.ge .Ldone

    mov x0, x20
    blr x19
    mov x21, x0

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x20
    mov x2, x21
    bl printk

    add x20, x20, #1
    b .Lloop

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
