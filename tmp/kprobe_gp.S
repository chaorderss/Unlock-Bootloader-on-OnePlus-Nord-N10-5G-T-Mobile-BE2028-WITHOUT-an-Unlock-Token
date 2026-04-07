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
sym_gp:     .asciz "gp_cds_context"
sym_gc:     .asciz "g_cds_context"
devname:    .asciz "wlan0"

fmt_gp:     .asciz "kgp: gp_cds=%px *gp=%px g_cds=%px *g=%px\n"
fmt_dump:   .asciz "kgp: gp+%03x: %016px %016px\n"
fmt_adapt:  .asciz "kgp: adapter=%px hdd_ctx=%px\n"
fmt_hdd:    .asciz "kgp: hdd_ctx+%03x: %016px %016px\n"

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

    /* Resolve gp_cds_context */
    adrp x0, sym_gp
    add x0, x0, :lo12:sym_gp
    bl kallsyms_lookup_name
    mov x19, x0        /* x19 = &gp_cds_context */

    /* Resolve g_cds_context */
    adrp x0, sym_gc
    add x0, x0, :lo12:sym_gc
    bl kallsyms_lookup_name
    mov x20, x0        /* x20 = &g_cds_context */

    /* Print both pointers and their deref values */
    adrp x0, fmt_gp
    add x0, x0, :lo12:fmt_gp
    mov x1, x19
    cbz x19, .Lskip_deref1
    ldr x2, [x19]
    b .Ldo_deref2
.Lskip_deref1:
    mov x2, xzr
.Ldo_deref2:
    mov x3, x20
    cbz x20, .Lskip_deref2
    ldr x4, [x20]
    b .Lprint_gp
.Lskip_deref2:
    mov x4, xzr
.Lprint_gp:
    bl printk

    /* Dump first 256 bytes of gp_cds_context struct (if non-null) */
    cbz x19, .Lget_adapter
    ldr x21, [x19]      /* deref pointer to pointer */
    cbz x21, .Lget_adapter

    mov x22, #0
.Ldump_gp:
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov x1, x22
    ldr x2, [x21, x22]
    add x23, x22, #8
    ldr x3, [x21, x23]
    bl printk
    add x22, x22, #16
    cmp x22, #256
    b.lt .Ldump_gp

.Lget_adapter:
    /* Get adapter from wlan0 */
    adrp x0, init_net
    add x0, x0, :lo12:init_net
    adrp x1, devname
    add x1, x1, :lo12:devname
    bl dev_get_by_name
    cbz x0, .Lret
    mov x21, x0        /* dev */
    add x22, x0, #0x880 /* adapter */

    /* hdd_ctx at adapter+0x18 */
    ldr x23, [x22, #0x18]

    adrp x0, fmt_adapt
    add x0, x0, :lo12:fmt_adapt
    mov x1, x22
    mov x2, x23
    bl printk

    cbz x23, .Lret

    /* Dump first 256 bytes of hdd_ctx */
    mov x24, #0
.Ldump_hdd:
    adrp x0, fmt_hdd
    add x0, x0, :lo12:fmt_hdd
    mov x1, x24
    ldr x2, [x23, x24]
    add x25, x24, #8
    ldr x3, [x23, x25]
    bl printk
    add x24, x24, #16
    cmp x24, #256
    b.lt .Ldump_hdd

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
