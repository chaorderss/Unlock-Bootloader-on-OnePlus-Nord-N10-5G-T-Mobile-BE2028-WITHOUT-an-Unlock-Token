/*
 * montx.S - Runtime patch to enable TX in monitor mode
 * Patches wlan0 netdev_ops to add ndo_start_xmit = hdd_hard_start_xmit
 *
 * Build:
 *   clang -target aarch64-linux-gnu -c -o montx.o montx.S
 *   ld.lld -r -o montx.ko montx.o
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
fmt_cur:     .asciz "montx: ops=%px xmit=%px\n"
fmt_found:   .asciz "montx: found xmit=%px selq=%px\n"
fmt_ok:      .asciz "montx: PATCHED ndo_start_xmit=%px\n"
fmt_exist:   .asciz "montx: xmit already set=%px\n"
fmt_fail:    .asciz "montx: FAILED\n"

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

    // dev = dev_get_by_name(&init_net, "wlan0")
    adrp x0, init_net
    add x0, x0, :lo12:init_net
    adrp x1, wlan0_str
    add x1, x1, :lo12:wlan0_str
    bl dev_get_by_name
    cbz x0, fail
    mov x19, x0

    // Read current netdev_ops
    ldr x20, [x19, #0x1f8]

    // Read ndo_start_xmit (+0x20)
    ldr x21, [x20, #0x20]

    // Print current state
    adrp x0, fmt_cur
    add x0, x0, :lo12:fmt_cur
    mov x1, x20
    mov x2, x21
    bl printk

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

    // Print found addresses
    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov x1, x22
    mov x2, x23
    bl printk

    // If xmit already set, skip
    cbnz x21, already_ok

    // Allocate new ops (512 bytes, GFP_KERNEL=0xcc0)
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

    // Replace netdev->netdev_ops
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
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret
