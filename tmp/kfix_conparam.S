/* kfix_conparam.S - Set the REAL con_mode used by hdd_get_conparam */

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

.section .plt,"ax"
.space 8
.section .init.plt,"ax"
.space 8
.section .text.ftrace_trampoline,"ax"
.space 8

.section .rodata, "a"
sym_func:   .asciz "hdd_get_conparam"
fmt_old:    .asciz "KFCP: hdd_get_conparam@%px -> data@%px, old=%d\n"
fmt_new:    .asciz "KFCP: patched to 4 (QDF_GLOBAL_MONITOR_MODE), verify=%d\n"
fmt_err:    .asciz "KFCP: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Find hdd_get_conparam */
    adrp x0, sym_func
    add x0, x0, :lo12:sym_func
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Decode ADRP at func+0: extract page offset */
    ldr w20, [x19]         /* ADRP instruction */
    /* immhi = bits[23:5] (19 bits), immlo = bits[30:29] (2 bits) */
    ubfx w21, w20, #5, #19   /* immhi */
    ubfx w22, w20, #29, #2   /* immlo */
    orr w21, w22, w21, lsl #2  /* imm21 = immhi:immlo */
    /* Sign extend 21-bit to 64-bit */
    sbfx x21, x21, #0, #21
    /* ADRP result = (PC & ~0xFFF) + (imm21 << 12) */
    and x22, x19, #0xfffffffffffff000
    add x22, x22, x21, lsl #12    /* x22 = ADRP result (page address) */

    /* Decode LDR at func+4: extract offset */
    ldr w20, [x19, #4]    /* LDR W0, [X8, #imm12] */
    ubfx w21, w20, #10, #12  /* imm12 for LDR W (scaled by 4) */
    add x22, x22, x21, lsl #2  /* x22 = actual data address */

    /* Read old value */
    ldr w20, [x22]

    /* Print */
    adrp x0, fmt_old
    add x0, x0, :lo12:fmt_old
    mov x1, x19
    mov x2, x22
    mov w3, w20
    bl printk

    /* Write 4 (QDF_GLOBAL_MONITOR_MODE) */
    mov w20, #4
    str w20, [x22]

    /* Verify */
    blr x19
    mov w20, w0

    adrp x0, fmt_new
    add x0, x0, :lo12:fmt_new
    mov w1, w20
    bl printk

    b .Ldone

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Ldone:
    mov x0, #-1
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
