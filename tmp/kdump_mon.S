/*
 * kdump_mon.S - Dump hdd_mon_open function + find device_mode offset
 * Also dumps first 256 bytes of mon0's adapter (netdev_priv)
 * Build: as -o kdump_mon.o kdump_mon.S && ld -r -o kdump_mon.ko kdump_mon.o
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
sym_mon:    .asciz "hdd_mon_open"
sym_devget: .asciz "dev_get_by_name"
sym_net:    .asciz "init_net"
sym_npriv:  .asciz "netdev_priv"
devname:    .asciz "mon0"

fmt_func:   .asciz "kdm: hdd_mon_open +%02x: %08x %08x %08x %08x\n"
fmt_dev:    .asciz "kdm: mon0 dev=%px\n"
fmt_priv:   .asciz "kdm: priv @ dev+%03x: %016llx %016llx\n"
fmt_err:    .asciz "kdm: error\n"

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
    stp x27, x28, [sp, #80]

    /* Resolve hdd_mon_open */
    adrp x0, sym_mon
    add x0, x0, :lo12:sym_mon
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Dump first 256 bytes of hdd_mon_open */
    mov w20, #0
.Ldump_func:
    cmp w20, #256
    b.ge .Ldev

    add x21, x19, x20
    ldr w22, [x21]
    ldr w23, [x21, #4]
    ldr w24, [x21, #8]
    ldr w25, [x21, #12]

    adrp x0, fmt_func
    add x0, x0, :lo12:fmt_func
    mov w1, w20
    mov w2, w22
    mov w3, w23
    mov w4, w24
    mov w5, w25
    bl printk

    add w20, w20, #16
    b .Ldump_func

.Ldev:
    /* Get mon0 net_device */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x26, x0
    cbz x0, .Lerr

    adrp x0, sym_net
    add x0, x0, :lo12:sym_net
    bl kallsyms_lookup_name
    mov x27, x0
    cbz x0, .Lerr

    mov x0, x27
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x26
    mov x28, x0
    cbz x0, .Lerr

    adrp x0, fmt_dev
    add x0, x0, :lo12:fmt_dev
    mov x1, x28
    bl printk

    /* Dump 256 bytes starting from dev+0x880 (likely priv area) */
    mov w20, #0x880
.Ldump_priv:
    mov w21, #0x980
    cmp w20, w21
    b.ge .Ldone

    add x22, x28, x20
    ldr x23, [x22]
    ldr x24, [x22, #8]

    adrp x0, fmt_priv
    add x0, x0, :lo12:fmt_priv
    mov w1, w20
    mov x2, x23
    mov x3, x24
    bl printk

    add w20, w20, #16
    b .Ldump_priv

.Ldone:
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
    ldp x27, x28, [sp, #80]
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
    .balign 8
    .space 8
.section .init.plt, "ax"
    .balign 8
    .space 8
.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
