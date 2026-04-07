/*
 * kprobe4.S - Scan TXRX context for non-NULL fields
 * Build: as -o kprobe4.o kprobe4.S && ld -r -o kprobe4.ko kprobe4.o
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
fmt_field:
    .asciz "kp4: txrx[0x%04x]=%px\n"
fmt_hdr:
    .asciz "kp4: txrx_ctx=%px, scanning for non-NULL fields...\n"
fmt_done:
    .asciz "kp4: scan done, found %d non-NULL fields\n"
fmt_nf:
    .asciz "kp4: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lnf
    mov x19, x0

    /* Get TXRX context */
    mov w0, #70
    blr x19
    mov x20, x0
    cbz x20, .Lnf

    adrp x0, fmt_hdr
    add x0, x0, :lo12:fmt_hdr
    mov x1, x20
    bl printk

    mov w21, #0          /* offset */
    mov w22, #0          /* count */

    /* Scan 0x0000 to 0xC000 (48KB) step 8 */
.Lscan:
    mov w8, #0xC000
    cmp w21, w8
    b.ge .Lsdone

    ldr x2, [x20, x21]
    cbz x2, .Lskip

    /* Only print first 100 non-NULL to avoid flood */
    cmp w22, #100
    b.ge .Lskip2

    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

.Lskip2:
    add w22, w22, #1
.Lskip:
    add w21, w21, #8
    b .Lscan

.Lsdone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    mov w1, w22
    bl printk

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
