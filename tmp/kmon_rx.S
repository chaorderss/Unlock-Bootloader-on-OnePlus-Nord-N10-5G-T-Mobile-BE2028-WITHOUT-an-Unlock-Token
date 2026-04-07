/*
 * kmon_rx.S - Call hdd_set_mon_rx_cb to register monitor RX callback
 *             Then call wma_cli_set_command to start channel
 */

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
    .quad 0
    .asciz "init_net"
    .balign 64, 0
    .quad 0
    .asciz "dev_get_by_name"
    .balign 64, 0

.section .rodata, "a"
sym_rxcb:   .asciz "hdd_set_mon_rx_cb"
sym_cli:    .asciz "wma_cli_set_command"
devname:    .asciz "wlan0"

fmt_dev:    .asciz "krx: dev=%px adapter=%px mode=%d\n"
fmt_rxcb:   .asciz "krx: hdd_set_mon_rx_cb(adapter) returned\n"
fmt_cli:    .asciz "krx: wma_cli_set_command(0, %d, %d, %d) = %d\n"
fmt_err:    .asciz "krx: error at step %d\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    /* Resolve hdd_set_mon_rx_cb */
    adrp x0, sym_rxcb
    add x0, x0, :lo12:sym_rxcb
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr1

    /* Resolve wma_cli_set_command */
    adrp x0, sym_cli
    add x0, x0, :lo12:sym_cli
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr1

    /* Get net device */
    adrp x0, init_net
    add x0, x0, :lo12:init_net
    adrp x1, devname
    add x1, x1, :lo12:devname
    bl dev_get_by_name
    mov x21, x0
    cbz x0, .Lerr2

    /* adapter = dev + 0x880 */
    add x22, x21, #0x880
    ldr w23, [x22, #0x48]  /* device_mode */

    adrp x0, fmt_dev
    add x0, x0, :lo12:fmt_dev
    mov x1, x21
    mov x2, x22
    mov w3, w23
    bl printk

    /* Call hdd_set_mon_rx_cb(adapter) */
    mov x0, x22
    blr x19

    adrp x0, fmt_rxcb
    add x0, x0, :lo12:fmt_rxcb
    bl printk

    /* Try wma_cli_set_command to set channel
     * wma_cli_set_command(vdev_id, param_id, sval, vpdev)
     *
     * Try WMI_PDEV_PARAM_MONITOR_CHAN = 0x801f
     * vpdev: 1 = PDEV_CMD, 2 = VDEV_CMD, 5 = GEN_CMD
     */

    /* Try 1: GEN_CMD with param 0x40 (WMA_VDEV_SET_MONITOR_CHAN) */
    mov w0, #0          /* vdev_id */
    mov w1, #0x801f     /* WMI_PDEV_PARAM_MONITOR_CHAN */
    mov w2, #2462       /* frequency for ch11 */
    mov w3, #1          /* PDEV_CMD */
    blr x20
    mov w24, w0

    adrp x0, fmt_cli
    add x0, x0, :lo12:fmt_cli
    mov w1, #0x801f
    mov w2, #2462
    mov w3, #1
    mov w4, w24
    bl printk

    /* Try 2: VDEV_CMD */
    mov w0, #0
    mov w1, #0x801f
    mov w2, #2462
    mov w3, #2          /* VDEV_CMD */
    blr x20
    mov w24, w0

    adrp x0, fmt_cli
    add x0, x0, :lo12:fmt_cli
    mov w1, #0x801f
    mov w2, #2462
    mov w3, #2
    mov w4, w24
    bl printk

    b .Lret

.Lerr1:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    mov w1, #1
    bl printk
    b .Lret

.Lerr2:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    mov w1, #2
    bl printk

.Lret:
    mov w0, #-1
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret

.section .note.Linux, "a", @note
    .long 6
    .long 0
    .long 0x100
    .asciz "Linux"
    .balign 4

.section .plt, "ax"
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
