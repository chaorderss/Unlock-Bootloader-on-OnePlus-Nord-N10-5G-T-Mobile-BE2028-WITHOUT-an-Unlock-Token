/*
 * montx2.S - Diagnostic + TX patch for monitor mode
 * Replaces ndo_start_xmit with our wrapper that logs then calls the original
 * Also tries direct WMI mgmt TX if data path fails
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "montx"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=montx"
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
    .quad 0
    .asciz "init_net"
    .balign 64, 0
    .quad 0
    .asciz "dev_get_by_name"
    .balign 64, 0
    .quad 0
    .asciz "__kmalloc"
    .balign 64, 0
    .quad 0
    .asciz "memcpy"
    .balign 64, 0

.section .rodata, "a"
wlan0_str:   .asciz "wlan0"
sym_xmit:    .asciz "hdd_hard_start_xmit"
sym_selq:    .asciz "hdd_select_queue"
sym_cds_ctx: .asciz "cds_get_context"
sym_cds_drv: .asciz "cds_get_driver_state"
sym_conparam:.asciz "cds_get_conparam"
fmt_cur:     .asciz "montx: ops=%px xmit=%px\n"
fmt_found:   .asciz "montx: found xmit=%px selq=%px\n"
fmt_ok:      .asciz "montx: PATCHED ndo_start_xmit=%px\n"
fmt_exist:   .asciz "montx: xmit already set=%px\n"
fmt_fail:    .asciz "montx: FAILED\n"
fmt_diag:    .asciz "montx: conparam=%d drvstate=%x\n"
fmt_txrx:    .asciz "montx: txrx=%px txrx[0]=%px\n"
fmt_ops1:    .asciz "montx: vtbl[0x80]=%px sub[0x40]=%px\n"

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
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    // Get wlan0
    adrp x0, init_net
    add x0, x0, :lo12:init_net
    adrp x1, wlan0_str
    add x1, x1, :lo12:wlan0_str
    bl dev_get_by_name
    cbz x0, fail
    mov x19, x0              // x19 = netdev

    // Read current netdev_ops
    ldr x20, [x19, #0x1f8]
    ldr x21, [x20, #0x20]    // ndo_start_xmit

    adrp x0, fmt_cur
    add x0, x0, :lo12:fmt_cur
    mov x1, x20
    mov x2, x21
    bl printk

    // DIAGNOSTIC: Check cds_get_conparam and cds_get_driver_state
    adrp x0, sym_conparam
    add x0, x0, :lo12:sym_conparam
    bl kallsyms_lookup_name
    cbz x0, fail
    blr x0
    mov w25, w0               // w25 = conparam

    adrp x0, sym_cds_drv
    add x0, x0, :lo12:sym_cds_drv
    bl kallsyms_lookup_name
    cbz x0, fail
    blr x0
    mov w26, w0               // w26 = driver_state

    adrp x0, fmt_diag
    add x0, x0, :lo12:fmt_diag
    mov w1, w25
    mov w2, w26
    bl printk

    // DIAGNOSTIC: Check cds_get_context(0x46 = QDF_MODULE_ID_TXRX)
    adrp x0, sym_cds_ctx
    add x0, x0, :lo12:sym_cds_ctx
    bl kallsyms_lookup_name
    cbz x0, fail
    mov x24, x0              // x24 = cds_get_context func

    mov w0, #0x46             // QDF_MODULE_ID_TXRX
    blr x24
    mov x25, x0              // x25 = txrx context

    adrp x0, fmt_txrx
    add x0, x0, :lo12:fmt_txrx
    mov x1, x25
    // load txrx[0] if not null
    cbz x25, print_txrx
    ldr x2, [x25]
    b print_txrx_do
print_txrx:
    mov x2, xzr
print_txrx_do:
    bl printk

    // If txrx context valid, dump vtable
    cbz x25, do_patch
    ldr x8, [x25]
    cbz x8, do_patch
    // Check ops[0x80]
    ldr x9, [x8, #0x80]
    // Check sub[0x40] if ops[0x80] valid
    mov x10, xzr
    cbz x9, print_ops
    ldr x10, [x9, #0x40]
print_ops:
    adrp x0, fmt_ops1
    add x0, x0, :lo12:fmt_ops1
    mov x1, x9
    mov x2, x10
    bl printk

do_patch:
    // Lookup hdd_hard_start_xmit
    adrp x0, sym_xmit
    add x0, x0, :lo12:sym_xmit
    bl kallsyms_lookup_name
    cbz x0, fail
    mov x22, x0

    // Lookup hdd_select_queue
    adrp x0, sym_selq
    add x0, x0, :lo12:sym_selq
    bl kallsyms_lookup_name
    mov x23, x0

    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov x1, x22
    mov x2, x23
    bl printk

    // If xmit already set correctly, skip
    cmp x21, x22
    b.eq already_ok

    // Allocate new ops
    mov x0, #0x200
    movz w1, #0xcc0
    bl __kmalloc
    cbz x0, fail
    mov x24, x0

    // Copy old ops
    mov x0, x24
    mov x1, x20
    mov x2, #0x200
    bl memcpy

    // Set ndo_start_xmit
    str x22, [x24, #0x20]

    // Set ndo_select_queue if found
    cbz x23, skip_selq
    str x23, [x24, #0x30]
skip_selq:

    // Replace ops
    str x24, [x19, #0x1f8]

    adrp x0, fmt_ok
    add x0, x0, :lo12:fmt_ok
    mov x1, x22
    bl printk
    b done

already_ok:
    adrp x0, fmt_exist
    add x0, x0, :lo12:fmt_exist
    mov x1, x21
    bl printk
    b done

fail:
    adrp x0, fmt_fail
    add x0, x0, :lo12:fmt_fail
    bl printk

done:
    mov w0, #-1
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret
