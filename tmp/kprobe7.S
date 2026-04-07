/*
 * kprobe7.S - Read ops[0x118] function pointer and dump its content
 * Build: as -o kprobe7.o kprobe7.S && ld -r -o kprobe7.ko kprobe7.o
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
    .quad 0
    .asciz "sprint_symbol"
    .balign 64, 0

.section .rodata, "a"
str_cds:
    .asciz "cds_get_context"
str_sprint:
    .asciz "sprint_symbol"
fmt_ops:
    .asciz "kp7: wmi_ops=%px ops[0x118]=%px\n"
fmt_name:
    .asciz "kp7: ops[0x118] = %s\n"
fmt_dump:
    .asciz "kp7: func+0x%03x: %08x\n"
fmt_err:
    .asciz "kp7: error\n"

.section .bss, "aw"
    .balign 8
sym_buf:
    .space 128

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    /* Resolve cds_get_context */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0

    /* Resolve sprint_symbol */
    adrp x0, str_sprint
    add x0, x0, :lo12:str_sprint
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0

    /* Get WMA context (ID=54) */
    mov w0, #54
    blr x19
    cbz x0, .Lerr

    /* Get wmi_handle = wma[0x0] */
    ldr x21, [x0]            /* x21 = wmi_handle */
    cbz x21, .Lerr

    /* Get ops = wmi_handle[0x278] */
    ldr x22, [x21, #0x278]   /* x22 = ops */
    cbz x22, .Lerr

    /* Get ops[0x118] = mgmt_cmd_send function pointer */
    ldr x23, [x22, #0x118]

    adrp x0, fmt_ops
    add x0, x0, :lo12:fmt_ops
    mov x1, x22
    mov x2, x23
    bl printk

    cbz x23, .Lerr

    /* sprint_symbol to get name */
    adrp x0, sym_buf
    add x0, x0, :lo12:sym_buf
    mov x1, x23
    blr x20

    adrp x0, fmt_name
    add x0, x0, :lo12:fmt_name
    adrp x1, sym_buf
    add x1, x1, :lo12:sym_buf
    bl printk

    /* Dump first 64 instructions of the function */
    mov w24, #0
.Ldump:
    cmp w24, #64
    b.ge .Ldone
    ldr w2, [x23, x24, lsl #2]
    lsl w1, w24, #2
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    bl printk
    add w24, w24, #1
    b .Ldump

.Ldone:
    mov w0, #0
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1
    ldp x23, x24, [sp, #48]
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
    .space 8
