/*
 * kdump_adapter.S - Dump wlan0 adapter struct to find device_mode offset
 * Dumps 512 bytes of adapter (netdev_priv area) and also checks known fields
 * Build: clang -target aarch64-linux-gnu -c && ld.lld -r
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
sym_devget: .asciz "dev_get_by_name"
sym_net:    .asciz "init_net"
devname:    .asciz "wlan0"

fmt_hdr:    .asciz "kda: wlan0 dev=%px priv starts at dev+0x880\n"
fmt_w32:    .asciz "kda: adapter+%03x: %08x %08x %08x %08x\n"
fmt_err:    .asciz "kda: error finding wlan0\n"

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

    /* Get wlan0 net_device */
    mov x0, x20
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19
    mov x21, x0          /* x21 = dev */
    cbz x0, .Lerr

    /* Print header */
    adrp x0, fmt_hdr
    add x0, x0, :lo12:fmt_hdr
    mov x1, x21
    bl printk

    /* Dump adapter (dev+0x880) as 32-bit words, 512 bytes total */
    mov w22, #0            /* offset from adapter start */
    add x23, x21, #0x880   /* x23 = adapter base = dev+0x880 */

.Ldump:
    cmp w22, #512
    b.ge .Ldone

    add x24, x23, x22
    ldr w1, [x24]
    ldr w2, [x24, #4]
    ldr w3, [x24, #8]
    ldr w4, [x24, #12]

    adrp x0, fmt_w32
    add x0, x0, :lo12:fmt_w32
    mov w25, w22           /* save offset */
    /* w1-w4 already set */
    /* but we need offset in w1 position... rearrange */
    mov w5, w4
    mov w4, w3
    mov w3, w2
    mov w2, w1
    mov w1, w25
    bl printk

    add w22, w22, #16
    b .Ldump

.Ldone:
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
