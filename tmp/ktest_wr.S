/*
 * ktest_wr.S - Test writing to wlan module text after set_memory_rw
 * Build: as -o ktest_wr.o ktest_wr.S && ld -r -o ktest_wr.ko ktest_wr.o
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

fmt_step:   .asciz "ktest: step %d\n"
fmt_before: .asciz "ktest: before: 0x%08x\n"
fmt_after:  .asciz "ktest: after:  0x%08x\n"
fmt_done:   .asciz "ktest: write test done\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    /* Step 1: resolve symbols */
    adrp x0, fmt_step
    add x0, x0, :lo12:fmt_step
    mov w1, #1
    bl printk

    adrp x0, sym_conv
    add x0, x0, :lo12:sym_conv
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Ldone

    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Ldone

    /* Step 2: read current instruction */
    adrp x0, fmt_step
    add x0, x0, :lo12:fmt_step
    mov w1, #2
    bl printk

    add x21, x19, #0x10         /* target address = convert_nl_iftype + 0x10 */
    ldr w22, [x21]              /* w22 = old instruction (0x528030e9) */

    adrp x0, fmt_before
    add x0, x0, :lo12:fmt_before
    mov w1, w22
    bl printk

    /* Step 3: set_memory_rw */
    adrp x0, fmt_step
    add x0, x0, :lo12:fmt_step
    mov w1, #3
    bl printk

    mov x0, x21
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x20                      /* set_memory_rw */

    /* Step 4: write new instruction */
    adrp x0, fmt_step
    add x0, x0, :lo12:fmt_step
    mov w1, #4
    bl printk

    mov w23, #0x38e9
    movk w23, #0x5280, lsl #16  /* 0x528038e9 = MOVZ W9, #0x1C7 */
    str w23, [x21]               /* WRITE! */

    /* Step 5: cache flush */
    adrp x0, fmt_step
    add x0, x0, :lo12:fmt_step
    mov w1, #5
    bl printk

    dc cvau, x21
    dsb ish
    ic ivau, x21
    dsb ish
    isb

    /* Step 6: verify */
    adrp x0, fmt_step
    add x0, x0, :lo12:fmt_step
    mov w1, #6
    bl printk

    ldr w24, [x21]
    adrp x0, fmt_after
    add x0, x0, :lo12:fmt_after
    mov w1, w24
    bl printk

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
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
