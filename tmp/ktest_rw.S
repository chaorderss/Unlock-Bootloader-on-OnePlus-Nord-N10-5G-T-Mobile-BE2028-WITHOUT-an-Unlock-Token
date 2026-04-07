/*
 * ktest_rw.S - Test if set_memory_rw works on wlan module text
 * Does NOT write anything! Just tests set_memory_rw and logs result.
 * Build: as -o ktest_rw.o ktest_rw.S && ld -r -o ktest_rw.ko ktest_rw.o
 */

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
sym_conv:   .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
sym_rwx:    .asciz "set_memory_rw"

fmt_addr:   .asciz "ktest: conv=%px rwx=%px\n"
fmt_insn:   .asciz "ktest: +0x10: 0x%08x\n"
fmt_rwx:    .asciz "ktest: set_memory_rw(%px, 1) returned %d\n"
fmt_read:   .asciz "ktest: after rwx, +0x10: 0x%08x\n"
fmt_done:   .asciz "ktest: done (no writes performed)\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Resolve symbols */
    adrp x0, sym_conv
    add x0, x0, :lo12:sym_conv
    bl kallsyms_lookup_name
    mov x19, x0

    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x20, x0

    /* Print addresses */
    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    mov x2, x20
    bl printk

    cbz x19, .Ldone
    cbz x20, .Ldone

    /* Read instruction at +0x10 */
    ldr w21, [x19, #0x10]
    adrp x0, fmt_insn
    add x0, x0, :lo12:fmt_insn
    mov w1, w21
    bl printk

    /* Call set_memory_rw on that page */
    add x21, x19, #0x10
    and x0, x21, #~0xFFF
    mov x1, #1
    blr x20
    mov w22, w0                  /* save return value */

    adrp x0, fmt_rwx
    add x0, x0, :lo12:fmt_rwx
    mov x1, x21
    mov w2, w22
    bl printk

    /* Read again to verify (just reading, no writing) */
    ldr w21, [x19, #0x10]
    adrp x0, fmt_read
    add x0, x0, :lo12:fmt_read
    mov w1, w21
    bl printk

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
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
    .space 8
