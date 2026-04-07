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

.section .plt,"ax"
.space 8
.section .init.plt,"ax"
.space 8
.section .text.ftrace_trampoline,"ax"
.space 8

.section .rodata, "a"
fmt_gp:   .asciz "CDS2: gp_cds_context@%px = %px, g_cds_struct@%px\n"
fmt_mac:  .asciz "CDS2: global_mac_context@%px = %px\n"
fmt_dump: .asciz "CDS2: cds+0x%03lx: %016lx %016lx\n"
fmt_cds:  .asciz "CDS2: cds_get_context(%d) = %px\n"
fmt_null: .asciz "CDS2: gp_cds_context is NULL!\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    // Read gp_cds_context at 0xffffffa45cdd80d8
    movz x19, #0x80d8
    movk x19, #0x5cdd, lsl #16
    movk x19, #0xa45c, lsl #32
    movk x19, #0xffff, lsl #48
    ldr x20, [x19]

    // g_cds_context struct address 0xffffffa45cdd7e58
    movz x21, #0x7e58
    movk x21, #0x5cdd, lsl #16
    movk x21, #0xa45c, lsl #32
    movk x21, #0xffff, lsl #48

    // Read global_mac_context at 0xffffffa45cd831f0
    movz x22, #0x31f0
    movk x22, #0x5cd8, lsl #16
    movk x22, #0xa45c, lsl #32
    movk x22, #0xffff, lsl #48
    ldr x23, [x22]

    // Print gp_cds_context
    adrp x0, fmt_gp
    add x0, x0, :lo12:fmt_gp
    mov x1, x19
    mov x2, x20
    mov x3, x21
    bl printk

    // Print global_mac_context
    adrp x0, fmt_mac
    add x0, x0, :lo12:fmt_mac
    mov x1, x22
    mov x2, x23
    bl printk

    // If gp_cds_context is NULL, skip
    cbz x20, .Lno_cds

    // Dump first 288 bytes of CDS context struct
    mov x25, x20
    mov x24, #0

.Ldump_loop:
    cmp x24, #288
    b.ge .Ldump_done

    ldr x2, [x25, x24]
    add x26, x24, #8
    ldr x3, [x25, x26]

    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov x1, x24
    bl printk

    add x24, x24, #16
    b .Ldump_loop

.Ldump_done:
    // Call cds_get_context for IDs 0-6
    movz x25, #0x02c8
    movk x25, #0x5ca2, lsl #16
    movk x25, #0xa45c, lsl #32
    movk x25, #0xffff, lsl #48

    mov x24, #0
.Lcds_loop:
    cmp x24, #7
    b.ge .Ldone

    mov x0, x24
    blr x25
    mov x26, x0

    adrp x0, fmt_cds
    add x0, x0, :lo12:fmt_cds
    mov x1, x24
    mov x2, x26
    bl printk

    add x24, x24, #1
    b .Lcds_loop

.Lno_cds:
    adrp x0, fmt_null
    add x0, x0, :lo12:fmt_null
    bl printk

.Ldone:
    mov x0, #-1
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
