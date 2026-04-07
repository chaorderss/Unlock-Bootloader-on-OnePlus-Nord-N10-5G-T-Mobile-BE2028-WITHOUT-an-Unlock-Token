/*
 * kread2.S - Safe kernel function dumper
 * Dumps convert_nl_iftype and change_iface functions
 * Uses printk with simple hex format
 * Build: as -o kread2.o kread2.S && ld -r -o kread2.ko kread2.o
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
str_func1:  .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
str_func2:  .asciz "wlan_hdd_cfg80211_change_iface"

fmt_addr:   .asciz "kread: %s @ %px\n"
fmt_hex4:   .asciz "kread: +%03lx: %08x %08x %08x %08x\n"
fmt_err:    .asciz "kread: ERROR symbol not found\n"
fmt_done:   .asciz "kread: done\n"

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

    /* ==========================================
     * Function 1: wlan_hdd_convert_nl_iftype_to_hdd_type
     * This is a short function, dump 128 bytes
     * ========================================== */
    adrp x19, str_func1
    add x19, x19, :lo12:str_func1
    mov x0, x19
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    mov x2, x20
    bl printk

    /* Dump 128 bytes */
    mov x21, #0
.Ld1:
    cmp x21, #128
    b.ge .Lfunc2

    add x22, x20, x21      /* x22 = base + offset */
    ldr w23, [x22]          /* word 0 */
    ldr w24, [x22, #4]     /* word 1 */
    ldr w25, [x22, #8]     /* word 2 */
    ldr w26, [x22, #12]    /* word 3 */

    adrp x0, fmt_hex4
    add x0, x0, :lo12:fmt_hex4
    mov x1, x21
    mov w2, w23
    mov w3, w24
    mov w4, w25
    mov w5, w26
    bl printk

    add x21, x21, #16
    b .Ld1

    /* ==========================================
     * Function 2: wlan_hdd_cfg80211_change_iface
     * Larger function, dump 512 bytes
     * ========================================== */
.Lfunc2:
    adrp x19, str_func2
    add x19, x19, :lo12:str_func2
    mov x0, x19
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    mov x2, x20
    bl printk

    mov x21, #0
.Ld2:
    cmp x21, #512
    b.ge .Ldone

    add x22, x20, x21
    ldr w23, [x22]
    ldr w24, [x22, #4]
    ldr w25, [x22, #8]
    ldr w26, [x22, #12]

    adrp x0, fmt_hex4
    add x0, x0, :lo12:fmt_hex4
    mov x1, x21
    mov w2, w23
    mov w3, w24
    mov w4, w25
    mov w5, w26
    bl printk

    add x21, x21, #16
    b .Ld2

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #-1
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1

.Lret:
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
