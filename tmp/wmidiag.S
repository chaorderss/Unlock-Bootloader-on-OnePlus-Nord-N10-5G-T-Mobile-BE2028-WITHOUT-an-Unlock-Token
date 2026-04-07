/* wmidiag.S - Diagnose why wma_tx_packet fails in monitor mode */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmidg"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmidg"
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
fmt1:      .asciz "wmidiag: mac_ctx=%px wma_intf_base=%px\n"
fmt2:      .asciz "wmidiag: vdev[%d]+0x10=%px vdev[%d]+0x18=%px\n"
fmt3:      .asciz "wmidiag: txrx=%px txrx[0]=%px\n"

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
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    // Lookup cds_get_context
    adrp x0, sym_cds
    add x0, x0, :lo12:sym_cds
    bl kallsyms_lookup_name
    cbz x0, done
    mov x19, x0               // x19 = cds_get_context

    // Get mac_ctx = cds_get_context(0x36)
    mov w0, #0x36
    blr x19
    cbz x0, done
    mov x20, x0               // x20 = mac_ctx

    // wma_intf_base = mac_ctx+0x2a0
    ldr x21, [x20, #0x2a0]    // x21 = wma_intf_base

    adrp x0, fmt1
    add x0, x0, :lo12:fmt1
    mov x1, x20
    mov x2, x21
    bl printk

    // Check vdev[0]
    cbz x21, check_txrx
    // vdev[0]+0x10
    ldr x3, [x21, #0x10]
    // vdev[0]+0x18
    ldr x4, [x21, #0x18]
    adrp x0, fmt2
    add x0, x0, :lo12:fmt2
    mov w1, #0
    mov w2, #0
    bl printk

    // Also check vdev[1]
    mov x8, #0x930
    add x22, x21, x8          // x22 = &vdev[1]
    ldr x3, [x22, #0x10]
    ldr x4, [x22, #0x18]
    adrp x0, fmt2
    add x0, x0, :lo12:fmt2
    mov w1, #1
    mov w2, #1
    bl printk

check_txrx:
    // Get txrx = cds_get_context(0x46)
    mov w0, #0x46
    blr x19
    mov x21, x0

    adrp x0, fmt3
    add x0, x0, :lo12:fmt3
    mov x1, x21
    cbz x21, print_txrx
    ldr x2, [x21]
    b do_print
print_txrx:
    mov x2, xzr
do_print:
    bl printk

done:
    mov w0, #-1
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret
