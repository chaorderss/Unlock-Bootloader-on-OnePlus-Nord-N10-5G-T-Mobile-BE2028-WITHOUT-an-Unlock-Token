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
sym_cds:    .asciz "cds_get_context"
sym_svs:    .asciz "send_vdev_start_cmd_tlv"
sym_wvs:    .asciz "wma_vdev_start"
fmt_ctx:    .asciz "kcds: cds_get_context(%d) = %px\n"
fmt_svs:    .asciz "kcds: send_vdev_start=%px wma_vdev_start=%px\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-80]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    adrp x0, sym_cds
    add x0, x0, :lo12:sym_cds
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lret

    adrp x0, sym_svs
    add x0, x0, :lo12:sym_svs
    bl kallsyms_lookup_name
    mov x22, x0

    adrp x0, sym_wvs
    add x0, x0, :lo12:sym_wvs
    bl kallsyms_lookup_name
    mov x23, x0

    adrp x0, fmt_svs
    add x0, x0, :lo12:fmt_svs
    mov x1, x22
    mov x2, x23
    bl printk

    mov x20, #0
.Lprobe:
    mov w0, w20
    blr x19
    mov x21, x0

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov w1, w20
    mov x2, x21
    bl printk

    add x20, x20, #1
    cmp x20, #16
    b.lt .Lprobe

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
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
