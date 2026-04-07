.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmidiag4"
    .fill 47, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0
.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmidiag4"
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
sym_cds: .asciz "cds_get_context"
fmt1: .asciz "wmd4: mac=%px [0x10]=%px [0x18]=%px [0x20]=%px\n"
fmt2: .asciz "wmd4: [0x20] byte+0x20=%d\n"
.section .plt, "ax"
    .quad 0
.section .init.plt, "ax"
    .quad 0
.section .text.ftrace_trampoline, "ax"
    .quad 0
.section .exit.text, "ax"
.global cleanup_module
.type cleanup_module, @function
cleanup_module:
    ret
.section .init.text, "ax"
.global init_module
.type init_module, @function
init_module:
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    stp x19, x20, [sp, #0x20]

    adrp x0, sym_cds
    add x0, x0, :lo12:sym_cds
    bl kallsyms_lookup_name
    cbz x0, done
    mov x19, x0

    mov w0, #0x36
    blr x19
    cbz x0, done
    mov x20, x0

    adrp x0, fmt1
    add x0, x0, :lo12:fmt1
    mov x1, x20
    ldr x2, [x20, #0x10]
    ldr x3, [x20, #0x18]
    ldr x4, [x20, #0x20]
    bl printk

    // Check [0x20] content - specifically byte at +0x20 (used as config byte for peer lookup)
    ldr x8, [x20, #0x20]
    cbz x8, done
    adrp x0, fmt2
    add x0, x0, :lo12:fmt2
    ldrb w1, [x8, #0x20]
    bl printk

done:
    mov w0, #-1
    ldp x19, x20, [sp, #0x20]
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ret
