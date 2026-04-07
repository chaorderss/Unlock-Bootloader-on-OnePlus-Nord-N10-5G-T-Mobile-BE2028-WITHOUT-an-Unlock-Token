/*
 * kmon_ndo.S - Patch ndo_open to hdd_mon_open and ensure device_mode=4
 *
 * netdev_ops at dev+0x1f8
 * ndo_open at ops+0x10
 * device_mode at adapter+0x48 (dev+0x8c8)
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
    .asciz "set_memory_rw"
    .balign 64, 0

.section .rodata, "a"
sym_devget:     .asciz "dev_get_by_name"
sym_net:        .asciz "init_net"
sym_mon_open:   .asciz "hdd_mon_open"
sym_set_rw:     .asciz "set_memory_rw"
devname:        .asciz "wlan0"

fmt_ops:    .asciz "kndo: ops=%px old_ndo_open=%px -> hdd_mon_open=%px\n"
fmt_dm:     .asciz "kndo: device_mode=%d (need 4)\n"
fmt_rw:     .asciz "kndo: set_memory_rw ret=%d\n"
fmt_done:   .asciz "kndo: ndo_open patched! Now: ip link set wlan0 up\n"
fmt_err:    .asciz "kndo: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    /* Resolve symbols */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    adrp x0, sym_net
    add x0, x0, :lo12:sym_net
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    adrp x0, sym_mon_open
    add x0, x0, :lo12:sym_mon_open
    bl kallsyms_lookup_name
    mov x23, x0       /* x23 = hdd_mon_open */
    cbz x0, .Lerr

    adrp x0, sym_set_rw
    add x0, x0, :lo12:sym_set_rw
    bl kallsyms_lookup_name
    mov x24, x0       /* x24 = set_memory_rw */
    cbz x0, .Lerr

    /* Get wlan0 */
    mov x0, x20
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19
    mov x21, x0       /* x21 = dev */
    cbz x0, .Lerr

    /* Check/set device_mode */
    add x22, x21, #0x880   /* adapter */
    ldr w1, [x22, #0x48]
    adrp x0, fmt_dm
    add x0, x0, :lo12:fmt_dm
    bl printk

    /* Set device_mode = 4 */
    mov w25, #4
    str w25, [x22, #0x48]

    /* Get netdev_ops at dev+0x1f8 */
    ldr x25, [x21, #0x1f8]   /* x25 = ops */
    ldr x26, [x25, #0x10]    /* x26 = current ndo_open */

    adrp x0, fmt_ops
    add x0, x0, :lo12:fmt_ops
    mov x1, x25
    mov x2, x26
    mov x3, x23
    bl printk

    /* Make ops page writable */
    mov x0, x25
    and x0, x0, #~0xFFF   /* page-align */
    mov x1, #1             /* 1 page */
    blr x24                /* set_memory_rw */

    adrp x0, fmt_rw
    add x0, x0, :lo12:fmt_rw
    mov w1, w0
    bl printk

    /* Write hdd_mon_open to ndo_open slot */
    str x23, [x25, #0x10]

    /* Cache maintenance */
    add x0, x25, #0x10
    dc cvau, x0
    dsb ish
    ic ivau, x0
    dsb ish
    isb

    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
    ldp x25, x26, [sp, #64]
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
