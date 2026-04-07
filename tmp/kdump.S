/*
 * kdump.S - Dump kernel function bytes via kallsyms
 * Reads 512 bytes from a function and prints as hex
 * Build: as -o kdump.o kdump.S && ld -r -o kdump.ko kdump.o
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
/* Function to dump - change this to dump different functions */
str_func:   .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
str_func2:  .asciz "wlan_hdd_cfg80211_change_iface"

fmt_addr: .asciz "kdump: %s @ %px\n"
fmt_hex:  .asciz "kdump: +%03x: %08x %08x %08x %08x\n"
fmt_err:  .asciz "kdump: symbol not found\n"
fmt_hdr:  .asciz "kdump: === Dumping %s ===\n"

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
    stp x27, x28, [sp, #80]

    /* === Dump function 1: convert_nl_iftype === */
    adrp x19, str_func
    add x19, x19, :lo12:str_func

    adrp x0, fmt_hdr
    add x0, x0, :lo12:fmt_hdr
    mov x1, x19
    bl printk

    mov x0, x19
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0            /* x20 = function address */

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    mov x2, x20
    bl printk

    /* Dump 256 bytes (64 instructions) in groups of 16 bytes */
    mov x21, #0             /* offset */
.Ldump1:
    cmp x21, #256
    b.ge .Lfunc2

    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov x1, x21
    ldr w2, [x20, x21]
    add x22, x21, #4
    ldr w3, [x20, x22]
    add x22, x21, #8
    ldr w4, [x20, x22]
    add x22, x21, #12
    ldr w5, [x20, x22]
    bl printk

    add x21, x21, #16
    b .Ldump1

    /* === Dump function 2: change_iface === */
.Lfunc2:
    adrp x19, str_func2
    add x19, x19, :lo12:str_func2

    adrp x0, fmt_hdr
    add x0, x0, :lo12:fmt_hdr
    mov x1, x19
    bl printk

    mov x0, x19
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    mov x2, x20
    bl printk

    /* Dump 512 bytes (128 instructions) */
    mov x21, #0
.Ldump2:
    cmp x21, #512
    b.ge .Ldone

    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov x1, x21
    ldr w2, [x20, x21]
    add x22, x21, #4
    ldr w3, [x20, x22]
    add x22, x21, #8
    ldr w4, [x20, x22]
    add x22, x21, #12
    ldr w5, [x20, x22]
    bl printk

    add x21, x21, #16
    b .Ldump2

.Ldone:
    mov w0, #-1         /* return error so module unloads immediately */
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1

.Lret:
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
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
