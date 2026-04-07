/*
 * wmidiag3.S - Check the specific vtable chain at wma_tx_packet:0x1d3f44
 * Checks: txrx->[0]->[0]->[0x180] and also vdev_handle
 */
.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmidiag3"
    .fill 47, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmidiag3"
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
sym_cds_ctx:  .asciz "cds_get_context"

fmt1: .asciz "wmd3: txrx=%px soc=%px\n"
fmt2: .asciz "wmd3: soc[0]=%px soc[0][0x180]=%px\n"
fmt3: .asciz "wmd3: mac=%px mac_2a0=%px vdev0_10=%px\n"
fmt4: .asciz "wmd3: soc[0x48]=%px soc[0x48][0x30]=%px\n"
fmt5: .asciz "wmd3: calling soc[0][0x180](vdev_handle)...\n"
fmt6: .asciz "wmd3: soc[0][0x180] returned %px\n"
fmt_fail: .asciz "wmd3: FAIL lookup\n"

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
    sub sp, sp, #0x80
    stp x29, x30, [sp, #0x70]
    add x29, sp, #0x70
    stp x19, x20, [sp, #0x60]
    stp x21, x22, [sp, #0x50]
    stp x23, x24, [sp, #0x40]

    // Lookup cds_get_context
    adrp x0, sym_cds_ctx
    add x0, x0, :lo12:sym_cds_ctx
    bl kallsyms_lookup_name
    cbz x0, fail
    mov x19, x0              // x19 = cds_get_context

    // Get txrx context (0x46)
    mov w0, #0x46
    blr x19
    cbz x0, fail
    mov x20, x0              // x20 = txrx

    // Read txrx[0] = soc
    ldr x21, [x20]           // x21 = soc

    adrp x0, fmt1
    add x0, x0, :lo12:fmt1
    mov x1, x20
    mov x2, x21
    bl printk

    cbz x21, skip_soc

    // Read soc[0] = ops (or whatever first member is)
    ldr x22, [x21]           // x22 = soc[0]
    mov x23, xzr             // x23 = soc[0][0x180] (init to 0)
    cbz x22, print_soc
    ldr x23, [x22, #0x180]   // x23 = soc[0][0x180] = function ptr

print_soc:
    adrp x0, fmt2
    add x0, x0, :lo12:fmt2
    mov x1, x22
    mov x2, x23
    bl printk

    // Also check soc[0x48] chain used later in wma_tx_packet
    ldr x1, [x21, #0x48]     // soc[0x48]
    mov x2, xzr
    cbz x1, print_soc48
    ldr x2, [x1, #0x30]      // soc[0x48][0x30]
print_soc48:
    stp x1, x2, [sp, #0x10]  // save for later
    adrp x0, fmt4
    add x0, x0, :lo12:fmt4
    ldp x1, x2, [sp, #0x10]
    bl printk

    // Get mac context (0x36) and check vdev array
    mov w0, #0x36
    blr x19
    cbz x0, skip_soc
    mov x24, x0              // x24 = mac_ctx

    ldr x1, [x24, #0x2a0]    // mac_ctx->vdev_array
    cbz x1, print_mac
    ldr x2, [x1, #0x10]      // vdev[0]+0x10 = vdev_handle
    b print_mac2
print_mac:
    mov x2, xzr
print_mac2:
    adrp x0, fmt3
    add x0, x0, :lo12:fmt3
    stp x1, x2, [sp, #0x10]
    mov x1, x24
    ldp x2, x3, [sp, #0x10]
    bl printk

    // If soc[0][0x180] is non-NULL AND vdev_handle is non-NULL, call it
    cbz x23, skip_soc        // no function
    ldr x0, [x24, #0x2a0]    // vdev_array
    cbz x0, skip_soc
    ldr x0, [x0, #0x10]      // vdev[0]+0x10 = vdev_handle
    cbz x0, skip_soc

    adrp x0, fmt5
    add x0, x0, :lo12:fmt5
    bl printk

    // Actually call the function
    ldr x8, [x24, #0x2a0]
    ldr x0, [x8, #0x10]      // vdev_handle
    blr x23                   // call soc[0][0x180](vdev_handle)
    mov x22, x0               // save result

    adrp x0, fmt6
    add x0, x0, :lo12:fmt6
    mov x1, x22
    bl printk

    b done

skip_soc:
    b done

fail:
    adrp x0, fmt_fail
    add x0, x0, :lo12:fmt_fail
    bl printk

done:
    mov w0, #-1
    ldp x23, x24, [sp, #0x40]
    ldp x21, x22, [sp, #0x50]
    ldp x19, x20, [sp, #0x60]
    ldp x29, x30, [sp, #0x70]
    add sp, sp, #0x80
    ret
