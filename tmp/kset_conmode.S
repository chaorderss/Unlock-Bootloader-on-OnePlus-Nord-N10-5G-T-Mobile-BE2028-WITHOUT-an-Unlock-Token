// kset_conmode.S - Set con_mode to 4 (QDF_GLOBAL_MONITOR_MODE)
// Also patches the con_mode in the adapter init check

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
sym_con:    .asciz "con_mode"
fmt_set:    .asciz "KCON: con_mode@%px: %d -> 4\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    stp x19, x20, [sp, #16]

    // Find con_mode
    adrp x0, sym_con
    add x0, x0, :lo12:sym_con
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone

    // Read current value
    ldr w20, [x19]

    // Print old value
    adrp x0, fmt_set
    add x0, x0, :lo12:fmt_set
    mov x1, x19
    mov w2, w20
    bl printk

    // Set con_mode = 4
    mov w8, #4
    str w8, [x19]

.Ldone:
    mov x0, #-1
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
