/*
 * kdump_jt.S - Dump change_iface jump table entries
 * Build: as -o kdump_jt.o kdump_jt.S && ld -r -o kdump_jt.ko kdump_jt.o
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
sym_chg:    .asciz "wlan_hdd_cfg80211_change_iface"
fmt_a:      .asciz "kjt: func=%px ADR_base=%px\n"
fmt_jt:     .asciz "kjt: table @ %px\n"
fmt_e:      .asciz "kjt: entry[%d] = %d (0x%08x) -> target=%px\n"

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

    adrp x0, sym_chg
    add x0, x0, :lo12:sym_chg
    bl kallsyms_lookup_name
    mov x19, x0                  /* func base */
    cbz x0, .Ldone

    /* ADR base = func + 0x1b4 */
    add x20, x19, #0x1b4

    adrp x0, fmt_a
    add x0, x0, :lo12:fmt_a
    mov x1, x19
    mov x2, x20
    bl printk

    /* Decode ADRP at func+0x19c */
    ldr w21, [x19, #0x19c]      /* ADRP instruction */
    ubfx w22, w21, #5, #19      /* immhi */
    ubfx w23, w21, #29, #2      /* immlo */
    orr w22, w23, w22, lsl #2
    sbfx x22, x22, #0, #21
    lsl x22, x22, #12
    add x23, x19, #0x19c
    and x23, x23, #~0xFFF
    add x22, x22, x23           /* target page */

    /* Decode ADD at func+0x1a0 */
    ldr w21, [x19, #0x1a0]
    ubfx w23, w21, #10, #12
    add x22, x22, x23           /* x22 = jump table base */

    adrp x0, fmt_jt
    add x0, x0, :lo12:fmt_jt
    mov x1, x22
    bl printk

    /* Dump entries 0-8 */
    mov w24, #0
.Ldump:
    cmp w24, #9
    b.ge .Ldone

    /* Load signed 32-bit entry */
    add x25, x22, x24, lsl #2   /* &table[i] */
    ldrsw x26, [x25]            /* sign-extended value */

    /* Compute target = ADR_base + entry */
    add x27, x20, x26

    adrp x0, fmt_e
    add x0, x0, :lo12:fmt_e
    mov w1, w24                  /* index */
    mov w2, w26                  /* signed offset */
    mov w3, w26                  /* hex value */
    mov x4, x27                  /* target addr */
    bl printk

    add w24, w24, #1
    b .Ldump

.Ldone:
    mov w0, #-1
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
