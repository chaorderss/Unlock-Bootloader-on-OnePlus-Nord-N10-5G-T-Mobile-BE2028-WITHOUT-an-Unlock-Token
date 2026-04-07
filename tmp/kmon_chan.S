/*
 * kmon_chan.S - Bypass con_mode check in wlan_hdd_set_mon_chan and call it
 *
 * wlan_hdd_set_mon_chan(adapter, chan_width, channel_or_freq)
 *
 * Step 1: NOP the B.NE at +0x030 (con_mode != 4 check)
 * Step 2: Get adapter via hdd_get_adapter(hdd_ctx, 4)
 * Step 3: Call wlan_hdd_set_mon_chan(adapter, 0, 11)
 *         If that fails, try (adapter, 0, 2462)
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
    .quad 0
    .asciz "set_memory_rw"
    .balign 64, 0

.section .rodata, "a"
sym_smc:    .asciz "wlan_hdd_set_mon_chan"
sym_ga:     .asciz "hdd_get_adapter"
sym_cds:    .asciz "cds_get_context"
sym_rw:     .asciz "set_memory_rw"

fmt_addr:   .asciz "kch: smc=%px ga=%px cds=%px\n"
fmt_patch:  .asciz "kch: patched +0x30: 0x%08x -> NOP\n"
fmt_ctx:    .asciz "kch: hdd_ctx=%px adapter=%px\n"
fmt_call:   .asciz "kch: set_mon_chan(adapter, %d, %d) = %d\n"
fmt_err:    .asciz "kch: error: %s is NULL\n"

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

    /* Resolve wlan_hdd_set_mon_chan */
    adrp x0, sym_smc
    add x0, x0, :lo12:sym_smc
    bl kallsyms_lookup_name
    mov x19, x0       /* x19 = set_mon_chan */
    cbz x0, .Lerr_smc

    /* Resolve hdd_get_adapter */
    adrp x0, sym_ga
    add x0, x0, :lo12:sym_ga
    bl kallsyms_lookup_name
    mov x20, x0       /* x20 = hdd_get_adapter */
    cbz x0, .Lerr_ga

    /* Resolve cds_get_context */
    adrp x0, sym_cds
    add x0, x0, :lo12:sym_cds
    bl kallsyms_lookup_name
    mov x21, x0       /* x21 = cds_get_context */
    cbz x0, .Lerr_cds

    /* Resolve set_memory_rw */
    adrp x0, sym_rw
    add x0, x0, :lo12:sym_rw
    bl kallsyms_lookup_name
    mov x22, x0       /* x22 = set_memory_rw */
    cbz x0, .Lerr_rw

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    mov x1, x19
    mov x2, x20
    mov x3, x21
    bl printk

    /* Step 1: NOP the B.NE at +0x030 */
    add x23, x19, #0x30
    ldr w24, [x23]         /* save old instruction */

    /* Make code page writable */
    mov x0, x23
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x22

    /* Write NOP */
    mov w25, #0x201f
    movk w25, #0xd503, lsl #16
    str w25, [x23]
    dc cvau, x23
    dsb ish
    ic ivau, x23
    dsb ish
    isb

    adrp x0, fmt_patch
    add x0, x0, :lo12:fmt_patch
    mov w1, w24
    bl printk

    /* Step 2: Get HDD context via cds_get_context(QDF_MODULE_ID_HDD=3) */
    mov w0, #3
    blr x21
    mov x23, x0        /* x23 = hdd_ctx */
    cbz x0, .Lerr_ctx

    /* Step 3: Get adapter via hdd_get_adapter(hdd_ctx, QDF_MONITOR_MODE=4) */
    mov x0, x23
    mov w1, #4
    blr x20
    mov x24, x0        /* x24 = adapter */

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x23
    mov x2, x24
    bl printk

    cbz x24, .Lerr_adapt

    /* Step 4: Call wlan_hdd_set_mon_chan(adapter, width=0, channel=11) */
    mov x0, x24         /* adapter */
    mov w1, #0          /* NL80211_CHAN_WIDTH_20_NOHT */
    mov w2, #11         /* channel 11 */
    blr x19
    mov w25, w0

    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    mov w1, #0
    mov w2, #11
    mov w3, w25
    bl printk

    /* If failed, try with freq 2462 */
    cbnz w25, .Ltry_freq
    b .Lret

.Ltry_freq:
    mov x0, x24
    mov w1, #0
    mov w2, #2462
    blr x19
    mov w25, w0

    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    mov w1, #0
    mov w2, #2462
    mov w3, w25
    bl printk
    b .Lret

.Lerr_smc:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_smc
    add x1, x1, :lo12:sym_smc
    bl printk
    b .Lret

.Lerr_ga:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_ga
    add x1, x1, :lo12:sym_ga
    bl printk
    b .Lret

.Lerr_cds:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_cds
    add x1, x1, :lo12:sym_cds
    bl printk
    b .Lret

.Lerr_rw:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_rw
    add x1, x1, :lo12:sym_rw
    bl printk
    b .Lret

.Lerr_ctx:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_cds
    add x1, x1, :lo12:sym_cds
    bl printk
    b .Lret

.Lerr_adapt:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_ga
    add x1, x1, :lo12:sym_ga
    bl printk
    b .Lret

.Lret:
    mov w0, #-1
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
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
