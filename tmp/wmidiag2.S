/* wmidiag2.S - More detailed WMA diagnostics */
.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmd2"
    .fill 51, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmd2"
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
sym_cds:   .asciz "cds_get_context"
f1:        .asciz "wmd2: mac=%px wma_base=%px\n"
f2:        .asciz "wmd2: vdev0: +0x10=%px +0x18=%px +0x131=%d\n"
f3:        .asciz "wmd2: wma_ctx(0x35)=%px txrx(0x46)=%px\n"
f4:        .asciz "wmd2: txrx_ops=%px ops40=%px ops40_20=%px\n"

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
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    adrp x0, sym_cds
    add x0, x0, :lo12:sym_cds
    bl kallsyms_lookup_name
    cbz x0, done
    mov x19, x0

    // mac_ctx = cds_get_context(0x36)
    mov w0, #0x36
    blr x19
    cbz x0, done
    mov x20, x0
    ldr x21, [x20, #0x2a0]   // wma_intf_base

    adrp x0, f1
    add x0, x0, :lo12:f1
    mov x1, x20
    mov x2, x21
    bl printk

    // vdev[0] details
    cbz x21, skip_vdev
    ldr x1, [x21, #0x10]     // +0x10
    ldr x2, [x21, #0x18]     // +0x18
    ldrb w3, [x21, #0x131]   // +0x131 (protection check)
    adrp x0, f2
    add x0, x0, :lo12:f2
    bl printk

skip_vdev:
    // wma_ctx = cds_get_context(0x35)
    mov w0, #0x35
    blr x19
    mov x22, x0

    // txrx = cds_get_context(0x46)
    mov w0, #0x46
    blr x19
    mov x23, x0

    adrp x0, f3
    add x0, x0, :lo12:f3
    mov x1, x22
    mov x2, x23
    bl printk

    // txrx vtable chain
    cbz x23, done
    ldr x1, [x23]            // txrx->ops
    cbz x1, done
    ldr x2, [x1, #0x40]      // ops->group_0x40
    mov x24, x2
    cbz x2, print_vtbl
    ldr x3, [x2, #0x20]      // group->func_0x20
    b print_vtbl2
print_vtbl:
    mov x3, xzr
print_vtbl2:
    adrp x0, f4
    add x0, x0, :lo12:f4
    bl printk

done:
    mov w0, #-1
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret
