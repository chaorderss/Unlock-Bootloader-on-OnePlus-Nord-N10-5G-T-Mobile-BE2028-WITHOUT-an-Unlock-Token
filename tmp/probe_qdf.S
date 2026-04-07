/*
 * probe_qdf.S - Dump contents of qdf_ctx from cds_get_context(64)
 * to verify it's a valid qdf_device_t before calling TX
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
fmt_init:
    .asciz "probe_qdf: init\n"
fmt_ctx:
    .asciz "probe_qdf: qdf_ctx=%px\n"
fmt_dump:
    .asciz "probe_qdf: [0x%03x] = %px\n"
fmt_done:
    .asciz "probe_qdf: done\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* Resolve cds_get_context */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Ldone
    mov x19, x0                /* x19 = cds_get_context */

    /* Get qdf_ctx */
    mov w0, #64               /* QDF_MODULE_ID_QDF_DEVICE */
    blr x19
    cbz x0, .Ldone
    mov x20, x0               /* x20 = qdf_ctx */

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x20
    bl printk

    /* Dump first 0x80 bytes of qdf_ctx struct */
    mov x21, #0
.Ldump:
    cmp x21, #0x80
    b.ge .Ldone

    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov x1, x21
    ldr x2, [x20, x21]
    bl printk

    add x21, x21, #8
    b .Ldump

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0

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
