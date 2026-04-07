/*
 * kprobe5.S - Explore TXRX vtable and WMA wmi_handle + interfaces
 * Build: as -o kprobe5.o kprobe5.S && ld -r -o kprobe5.ko kprobe5.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kfind"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kfind"
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
str_cds:
    .asciz "cds_get_context"
fmt_txrx:
    .asciz "kp5: txrx=%px txrx[0]=%px\n"
fmt_vt:
    .asciz "kp5: vtable[0x%02x]=%px\n"
fmt_wma:
    .asciz "kp5: wma=%px wmi_handle=%px interfaces=%px\n"
fmt_iface:
    .asciz "kp5: iface0[0x%04x]=%px\n"
fmt_wmi:
    .asciz "kp5: wmi[0x%04x]=%px\n"
fmt_err:
    .asciz "kp5: error\n"

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

    /* Resolve cds_get_context */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0

    /* Get TXRX context (ID=70) */
    mov w0, #70
    blr x19
    cbz x0, .Lerr
    mov x20, x0              /* x20 = txrx */

    /* Print txrx and its first field (vtable) */
    ldr x21, [x20]           /* x21 = txrx[0] = vtable pointer */
    adrp x0, fmt_txrx
    add x0, x0, :lo12:fmt_txrx
    mov x1, x20
    mov x2, x21
    bl printk

    /* Dump vtable entries 0x00-0xF8 (32 entries) */
    cbz x21, .Ldo_wma
    mov w22, #0
.Lvt_loop:
    cmp w22, #256             /* scan vtable 0x00-0xFF (32 entries * 8 bytes) */
    b.ge .Ldo_wma
    ldr x2, [x21, x22]
    cbz x2, .Lvt_skip
    adrp x0, fmt_vt
    add x0, x0, :lo12:fmt_vt
    mov w1, w22
    bl printk
.Lvt_skip:
    add w22, w22, #8
    b .Lvt_loop

.Ldo_wma:
    /* Get WMA context (ID=54) */
    mov w0, #54
    blr x19
    cbz x0, .Lerr
    mov x23, x0              /* x23 = wma */

    ldr x24, [x23]           /* x24 = wma[0x0] = wmi_handle */
    ldr x25, [x23, #0x2a0]   /* x25 = wma[0x2a0] = interfaces */

    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov x1, x23
    mov x2, x24
    mov x3, x25
    bl printk

    /* Dump WMI handle fields 0x00-0x300 */
    cbz x24, .Ldo_iface
    mov w22, #0
.Lwmi_loop:
    mov w8, #0x300
    cmp w22, w8
    b.ge .Ldo_iface
    ldr x2, [x24, x22]
    cbz x2, .Lwmi_skip
    adrp x0, fmt_wmi
    add x0, x0, :lo12:fmt_wmi
    mov w1, w22
    bl printk
.Lwmi_skip:
    add w22, w22, #8
    b .Lwmi_loop

.Ldo_iface:
    /* Dump interfaces[0] first 0x100 bytes */
    cbz x25, .Ldone
    mov w22, #0
.Liface_loop:
    mov w8, #0x100
    cmp w22, w8
    b.ge .Ldone
    ldr x2, [x25, x22]
    cbz x2, .Liface_skip
    adrp x0, fmt_iface
    add x0, x0, :lo12:fmt_iface
    mov w1, w22
    bl printk
.Liface_skip:
    add w22, w22, #8
    b .Liface_loop

.Ldone:
    mov w0, #0
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
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
