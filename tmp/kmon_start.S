/*
 * kmon_start.S - Call hdd_start_adapter(adapter) with device_mode=4
 *                to create MONITOR VDEV in firmware
 *
 * adapter = dev + 0x880 (netdev_priv)
 * adapter->device_mode at adapter+0x48 (already set to 4)
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

.section .rodata, "a"
sym_devget:     .asciz "dev_get_by_name"
sym_net:        .asciz "init_net"
sym_start:      .asciz "hdd_start_adapter"
devname:        .asciz "wlan0"

fmt_pre:    .asciz "kst: adapter=%px device_mode=%d calling hdd_start_adapter...\n"
fmt_ret:    .asciz "kst: hdd_start_adapter returned %d\n"
fmt_err:    .asciz "kst: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    /* Resolve dev_get_by_name */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Resolve init_net */
    adrp x0, sym_net
    add x0, x0, :lo12:sym_net
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    /* Resolve hdd_start_adapter */
    adrp x0, sym_start
    add x0, x0, :lo12:sym_start
    bl kallsyms_lookup_name
    mov x23, x0       /* x23 = hdd_start_adapter */
    cbz x0, .Lerr

    /* Get wlan0 */
    mov x0, x20
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19
    mov x21, x0       /* x21 = dev */
    cbz x0, .Lerr

    /* adapter = dev + 0x880 */
    add x22, x21, #0x880

    /* Verify device_mode is 4 and print */
    ldr w1, [x22, #0x48]
    adrp x0, fmt_pre
    add x0, x0, :lo12:fmt_pre
    mov x24, x22       /* save adapter for call */
    /* x1 already has device_mode */
    /* but adrp/add clobbered x0 before we could use x22 */
    mov x2, x22        /* adapter ptr for %px format... but format expects px first then d */
    /* Let me redo properly */
    mov x19, x22       /* save adapter in x19 (was dev_get, done with it) */
    ldr w20, [x22, #0x48]  /* save device_mode in w20 */

    adrp x0, fmt_pre
    add x0, x0, :lo12:fmt_pre
    mov x1, x19        /* adapter */
    mov w2, w20         /* device_mode */
    bl printk

    /* Ensure device_mode = 4 */
    mov w0, #4
    str w0, [x19, #0x48]

    /* Call hdd_start_adapter(adapter) */
    mov x0, x19
    blr x23

    /* Save return value */
    mov w24, w0

    /* Print result */
    adrp x0, fmt_ret
    add x0, x0, :lo12:fmt_ret
    mov w1, w24
    bl printk

    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
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
    .balign 8
    .space 8
.section .init.plt, "ax"
    .balign 8
    .space 8
.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
