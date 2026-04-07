/*
 * kmon_init.S - Call hdd_mon_open to init monitor mode on mon0
 * Build: as -o kmon_init.o kmon_init.S && ld -r -o kmon_init.ko kmon_init.o
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
devname:    .asciz "mon0"

fmt_info:   .asciz "kmi: mon_open=%px dev=%px\n"
fmt_call:   .asciz "kmi: calling hdd_mon_open...\n"
fmt_ret:    .asciz "kmi: hdd_mon_open returned %d\n"
fmt_err:    .asciz "kmi: error: sym not found or dev not found\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Resolve hdd_mon_open */
    adrp x0, sym_mon
    add x0, x0, :lo12:sym_mon
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Resolve dev_get_by_name */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    /* Resolve init_net */
    adrp x0, sym_net
    add x0, x0, :lo12:sym_net
    bl kallsyms_lookup_name
    mov x21, x0
    cbz x0, .Lerr

    /* Get mon0 net_device */
    mov x0, x21
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x20
    mov x22, x0
    cbz x0, .Lerr

    adrp x0, fmt_info
    add x0, x0, :lo12:fmt_info
    mov x1, x19
    mov x2, x22
    bl printk

    /* Call hdd_mon_open(mon0_dev) */
    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    bl printk

    mov x0, x22                  /* net_device for mon0 */
    blr x19                      /* hdd_mon_open(dev) */
    mov w21, w0                  /* save return value */

    adrp x0, fmt_ret
    add x0, x0, :lo12:fmt_ret
    mov w1, w21
    bl printk
    b .Ldone

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Ldone:
    mov w0, #-1
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
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
