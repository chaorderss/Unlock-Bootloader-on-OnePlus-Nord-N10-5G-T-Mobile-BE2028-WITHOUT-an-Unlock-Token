/*
 * kprobe2.S - Read gp_cds_context and scan for WMA handle
 * Build: as -o kprobe2.o kprobe2.S && ld -r -o kprobe2.ko kprobe2.o
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
str_gp_cds:
    .asciz "gp_cds_context"
str_wma_open:
    .asciz "wma_open"
fmt_gp:
    .asciz "kprobe2: gp_cds_context @ %px, value=%px\n"
fmt_scan:
    .asciz "kprobe2: cds_ctx+0x%03x = %px\n"
fmt_wma:
    .asciz "kprobe2: wma_open @ %px\n"
fmt_nf:
    .asciz "kprobe2: symbol not found\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Look up gp_cds_context */
    adrp x0, str_gp_cds
    add x0, x0, :lo12:str_gp_cds
    bl kallsyms_lookup_name
    cbz x0, .Lnf
    mov x19, x0   /* x19 = &gp_cds_context */

    /* Read the pointer */
    ldr x20, [x19]  /* x20 = gp_cds_context (the actual struct pointer) */

    adrp x0, fmt_gp
    add x0, x0, :lo12:fmt_gp
    mov x1, x19
    mov x2, x20
    bl printk

    /* Also print wma_open address for reference */
    adrp x0, str_wma_open
    add x0, x0, :lo12:str_wma_open
    bl kallsyms_lookup_name
    mov x21, x0
    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov x1, x21
    bl printk

    /* Scan cds_context struct for interesting pointers
     * Print every 8-byte field from offset 0 to 0x200
     */
    cbz x20, .Ldone
    mov w22, #0     /* offset */
.Lscan:
    cmp w22, #0x200
    b.ge .Ldone

    ldr x2, [x20, x22]     /* read qword at offset */
    cbz x2, .Lskip          /* skip NULL */

    adrp x0, fmt_scan
    add x0, x0, :lo12:fmt_scan
    mov w1, w22
    /* x2 already set */
    bl printk

.Lskip:
    add w22, w22, #8
    b .Lscan

.Ldone:
    mov w0, #0
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.Lnf:
    adrp x0, fmt_nf
    add x0, x0, :lo12:fmt_nf
    bl printk
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
