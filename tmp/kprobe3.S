/*
 * kprobe3.S - Check TXRX context fields that wma_tx_packet accesses
 * Build: as -o kprobe3.o kprobe3.S && ld -r -o kprobe3.ko kprobe3.o
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
    .asciz "kp3: txrx_ctx(70)=%px\n"
fmt_field:
    .asciz "kp3: txrx[0x%04x]=%px\n"
fmt_wma:
    .asciz "kp3: wma[0x%04x]=%px\n"
fmt_wma_byte:
    .asciz "kp3: wma_byte[0x%03x]=%d\n"
fmt_nf:
    .asciz "kp3: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Get cds_get_context */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lnf
    mov x19, x0

    /* Get TXRX context (module ID 70) */
    mov w0, #70
    blr x19
    mov x20, x0

    adrp x0, fmt_txrx
    add x0, x0, :lo12:fmt_txrx
    mov x1, x20
    bl printk

    cbz x20, .Ldone

    /* Check txrx_ctx fields accessed by wma_tx_packet:
     * With frmType=0: txrx[0x10]
     * With frmType=1: txrx[0x4940]
     * With frmType=2: txrx[0x9270]
     * Also check txrx[0x00], txrx[0x08], txrx[0x18]
     */
    mov w21, #0x00
    ldr x2, [x20, x21]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    mov w21, #0x08
    ldr x2, [x20, x21]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    mov w21, #0x10
    ldr x2, [x20, x21]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    mov w21, #0x18
    ldr x2, [x20, x21]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    /* frmType=1 fields (0x4930 + offset) */
    mov w21, #0x4930
    add x22, x20, x21
    ldr x2, [x22]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    add w21, w21, #0x08
    add x22, x20, x21
    ldr x2, [x22]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    mov w21, #0x4940
    add x22, x20, x21
    ldr x2, [x22]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    mov w21, #0x4948
    add x22, x20, x21
    ldr x2, [x22]
    adrp x0, fmt_field
    add x0, x0, :lo12:fmt_field
    mov w1, w21
    bl printk

    /* Also check WMA context fields */
    mov w0, #54
    blr x19
    mov x20, x0
    cbz x20, .Ldone

    /* wma+0x20 (byte), wma+0x2a4 */
    ldrb w2, [x20, #0x20]
    adrp x0, fmt_wma_byte
    add x0, x0, :lo12:fmt_wma_byte
    mov w1, #0x20
    bl printk

    /* wma+0x2a4 is where interfaces lives */
    mov w21, #0x2a0
    add x22, x20, x21
    ldr x2, [x22]
    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov w1, #0x2a0
    bl printk

    add w21, w21, #0x08
    add x22, x20, x21
    ldr x2, [x22]
    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov w1, w21
    bl printk

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
