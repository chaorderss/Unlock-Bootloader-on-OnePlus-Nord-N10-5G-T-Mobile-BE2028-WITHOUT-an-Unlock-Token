/*
 * kdump_ops.S - Find netdev_ops in net_device struct by scanning for hdd_open address
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
sym_hdd_open:   .asciz "hdd_open"
devname:        .asciz "wlan0"

fmt_hdr:    .asciz "kdo: dev=%px hdd_open=%px\n"
fmt_dump:   .asciz "kdo: dev+%03x: %016llx %016llx\n"
fmt_found:  .asciz "kdo: FOUND! netdev_ops at dev+%03x, ops=%px, ndo_open=%px\n"
fmt_err:    .asciz "kdo: error\n"

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

    adrp x0, sym_hdd_open
    add x0, x0, :lo12:sym_hdd_open
    bl kallsyms_lookup_name
    mov x25, x0            /* x25 = hdd_open address */
    cbz x0, .Lerr

    mov x0, x20
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19
    mov x21, x0            /* x21 = dev */
    cbz x0, .Lerr

    adrp x0, fmt_hdr
    add x0, x0, :lo12:fmt_hdr
    mov x1, x21
    mov x2, x25
    bl printk

    /* Dump dev+0x1e0..0x300 and search for a pointer whose [+0x10] = hdd_open */
    mov w22, #0x1e0

.Ldump:
    cmp w22, #0x300
    b.ge .Lnot_found

    add x23, x21, x22
    ldr x26, [x23]         /* candidate pointer at dev+offset */
    ldr x27, [x23, #8]

    /* Print this entry */
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w22
    mov x2, x26
    mov x3, x27
    bl printk

    /* Check if candidate is a kernel pointer (top byte 0xff) */
    lsr x28, x26, #56
    cmp x28, #0xff
    b.ne .Lnext

    /* Try to read candidate+0x10 (ndo_open slot) */
    /* Compare with hdd_open */
    ldr x28, [x26, #0x10]
    cmp x28, x25
    b.ne .Lnext

    /* Found netdev_ops! */
    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov w1, w22
    mov x2, x26
    mov x3, x28
    bl printk
    b .Ldone

.Lnext:
    add w22, w22, #8
    b .Ldump

.Lnot_found:
    /* Also try offset range 0x300..0x400 */
    mov w22, #0x300

.Ldump2:
    cmp w22, #0x400
    b.ge .Ldone

    add x23, x21, x22
    ldr x26, [x23]

    lsr x28, x26, #56
    cmp x28, #0xff
    b.ne .Lnext2

    ldr x28, [x26, #0x10]
    cmp x28, x25
    b.ne .Lnext2

    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov w1, w22
    mov x2, x26
    mov x3, x28
    bl printk
    b .Ldone

.Lnext2:
    add w22, w22, #8
    b .Ldump2

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
