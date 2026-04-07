/*
 * kdump_combo.S - Dump wiphy iface_combination structure
 * sizeof(ieee80211_iface_combination) = 24 bytes on arm64
 * sizeof(ieee80211_iface_limit) = 4 bytes (u16 max, u16 types)
 *
 * Build: as -o kdump_combo.o kdump_combo.S && ld -r -o kdump_combo.ko kdump_combo.o
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
str_comb:       .asciz "wlan_hdd_iface_combination"

fmt_addr:       .asciz "kcomb: iface_combination @ %px\n"
fmt_raw:        .asciz "kcomb: combo[%d] raw: %016llx %08x %04x n=%d\n"
fmt_limit:      .asciz "kcomb:   limit[%d]: max=%d types=0x%04x\n"
fmt_err:        .asciz "kcomb: ERROR\n"
fmt_done:       .asciz "kcomb: done\n"
fmt_wiphy:      .asciz "kcomb: wiphy n_iface_combinations = reading from iw output\n"

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

    adrp x0, str_comb
    add x0, x0, :lo12:str_comb
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0            /* x19 = iface_combination array */

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    bl printk

    /* Dump 12 combinations (the iw output showed ~10)
     * sizeof(struct ieee80211_iface_combination) = 24 bytes on arm64
     * Actually let me check: it has a pointer (8), u32 (4), u16 (2), u8 (1), bool (1),
     * u8 (1), u8 (1), pad (2), u32 (4) = 24 bytes
     * But compiler might add padding to make it 32 for alignment.
     * Let me dump raw bytes to figure out the actual size.
     */

    /* Dump raw memory: 384 bytes = enough for 12 combos at 24 bytes or 12 at 32 */
    mov x20, x19           /* current ptr */
    mov w21, #0             /* index */

.Ldump:
    cmp w21, #12
    b.ge .Ldone

    /* Read raw fields assuming 24-byte struct */
    ldr x22, [x20]         /* limits ptr (+0x00) */
    ldr w23, [x20, #8]     /* num_different_channels (+0x08) */
    ldrh w24, [x20, #12]   /* max_interfaces (+0x0c) */
    ldrb w25, [x20, #14]   /* n_limits (+0x0e) */

    adrp x0, fmt_raw
    add x0, x0, :lo12:fmt_raw
    mov w1, w21
    mov x2, x22             /* limits ptr */
    mov w3, w23             /* num_diff_ch */
    mov w4, w24             /* max_if */
    mov w5, w25             /* n_limits */
    bl printk

    /* If n_limits > 0 and limits ptr looks valid, dump limits */
    cbz w25, .Lnext
    cmp x22, #0x1000
    b.lo .Lnext             /* skip if ptr looks invalid */

    /* Dump up to 4 limits */
    mov x26, x22            /* x26 = limits array */
    mov w27, #0             /* limit index */

.Ldump_limit:
    cmp w27, w25
    b.ge .Lnext
    cmp w27, #4
    b.ge .Lnext

    ldrh w28, [x26]         /* max */
    ldrh w23, [x26, #2]     /* types */

    /* Save volatile regs before printk */
    str x26, [sp, #88]      /* reuse stp slot */

    adrp x0, fmt_limit
    add x0, x0, :lo12:fmt_limit
    mov w1, w27
    mov w2, w28
    mov w3, w23
    bl printk

    ldr x26, [sp, #88]      /* restore */
    add x26, x26, #4        /* next limit (4 bytes each) */
    add w27, w27, #1
    b .Ldump_limit

.Lnext:
    add x20, x20, #24       /* next combination */
    add w21, w21, #1
    b .Ldump

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #-1              /* fail to stay unloaded */
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
