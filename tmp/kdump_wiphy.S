/*
 * kdump_wiphy.S - Dump wiphy struct to find interface_modes offset
 * Strategy: get wlan0 netdev → wdev → wiphy, search for iface_combinations ptr
 * Build: as -o kdump_wiphy.o kdump_wiphy.S && ld -r -o kdump_wiphy.ko kdump_wiphy.o
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
sym_devget:     .asciz "dev_get_by_name"
sym_initnet:    .asciz "init_net"
sym_combo:      .asciz "wlan_hdd_iface_combination"
devname:        .asciz "wlan0"

fmt_dev:        .asciz "kwi: netdev=%px wdev=%px wiphy=%px\n"
fmt_combo:      .asciz "kwi: iface_combination=%px\n"
fmt_hex:        .asciz "kwi: wiphy+%03x: %016llx %016llx\n"
fmt_found:      .asciz "kwi: FOUND combo ptr at wiphy+%03x!\n"
fmt_modes:      .asciz "kwi: interface_modes candidate at wiphy+%03x = 0x%04x\n"
fmt_err:        .asciz "kwi: ERROR resolving %s\n"
fmt_nodev:      .asciz "kwi: wlan0 not found\n"
fmt_done:       .asciz "kwi: done\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]

    /* Resolve dev_get_by_name */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x19, x0                  /* x19 = dev_get_by_name */
    cbnz x0, 1f
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_devget
    add x1, x1, :lo12:sym_devget
    bl printk
    b .Lfail
1:
    /* Resolve init_net */
    adrp x0, sym_initnet
    add x0, x0, :lo12:sym_initnet
    bl kallsyms_lookup_name
    mov x20, x0                  /* x20 = &init_net */
    cbnz x0, 2f
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_initnet
    add x1, x1, :lo12:sym_initnet
    bl printk
    b .Lfail
2:
    /* Resolve wlan_hdd_iface_combination for reference */
    adrp x0, sym_combo
    add x0, x0, :lo12:sym_combo
    bl kallsyms_lookup_name
    mov x21, x0                  /* x21 = &iface_combination */
    adrp x0, fmt_combo
    add x0, x0, :lo12:fmt_combo
    mov x1, x21
    bl printk

    /* Call dev_get_by_name(&init_net, "wlan0") */
    mov x0, x20                  /* &init_net */
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19                      /* dev_get_by_name */
    mov x22, x0                  /* x22 = net_device* */
    cbnz x0, 3f
    adrp x0, fmt_nodev
    add x0, x0, :lo12:fmt_nodev
    bl printk
    b .Lfail
3:
    /* Get wdev = dev->ieee80211_ptr at offset 0x2D8 */
    ldr x23, [x22, #0x2D8]      /* x23 = wdev */

    /* Get wiphy = wdev->wiphy at offset 0 */
    ldr x24, [x23]               /* x24 = wiphy */

    adrp x0, fmt_dev
    add x0, x0, :lo12:fmt_dev
    mov x1, x22
    mov x2, x23
    mov x3, x24
    bl printk

    /* Dump first 512 bytes of wiphy in 16-byte chunks, looking for combo ptr */
    mov w25, #0                  /* offset */

.Ldump:
    cmp w25, #512
    b.ge .Ldone

    /* Read 16 bytes */
    add x26, x24, x25
    ldr x27, [x26]              /* first 8 bytes */
    ldr x28, [x26, #8]          /* next 8 bytes */

    /* Print hex dump */
    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov w1, w25
    mov x2, x27
    mov x3, x28
    bl printk

    /* Check if x27 matches combo ptr */
    cmp x27, x21
    b.ne 4f
    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov w1, w25
    bl printk
4:
    /* Check if x28 matches combo ptr */
    cmp x28, x21
    b.ne 5f
    add w26, w25, #8
    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov w1, w26
    bl printk
5:
    add w25, w25, #16
    b .Ldump

.Ldone:
    /* Also check some specific offsets for u16 values that look like interface modes */
    /* Common offsets to check: scan backward from combo ptr */

    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #-1
    b .Lret

.Lfail:
    mov w0, #-1

.Lret:
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #112
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
