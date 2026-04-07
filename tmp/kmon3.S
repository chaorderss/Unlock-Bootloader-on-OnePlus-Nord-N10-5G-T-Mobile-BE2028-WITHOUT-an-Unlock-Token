/*
 * kmon3.S - Enable monitor mode by patching wiphy iface combinations
 *
 * The driver registers iface_combinations that exclude monitor mode.
 * cfg80211 rejects monitor before even calling the driver.
 *
 * Strategy:
 * 1. Patch bitmask in convert_nl_iftype (allow monitor in driver)
 * 2. Patch lookup table (map monitor to QDF_MONITOR_MODE=4)
 * 3. Find wiphy->iface_combinations and add a monitor-only combination
 *    OR just patch the allowed_iftypes in an existing combination
 *
 * First, dump the iface_combination structure to understand layout.
 *
 * struct ieee80211_iface_combination {
 *     const struct ieee80211_iface_limit *limits;  // +0x00 (8 bytes)
 *     u32 num_different_channels;                  // +0x08 (4 bytes)
 *     u16 max_interfaces;                          // +0x0c (2 bytes)
 *     u8 n_limits;                                 // +0x0e (1 byte)
 *     bool beacon_int_infra_match;                 // +0x0f (1 byte)
 *     ... more fields
 * };
 *
 * struct ieee80211_iface_limit {
 *     u16 max;      // +0x00
 *     u16 types;    // +0x02  (bitmask of BIT(NL80211_IFTYPE_*))
 * };
 *
 * NL80211_IFTYPE_MONITOR = 6, so BIT(6) = 0x40
 *
 * Build: as -o kmon3.o kmon3.S && ld -r -o kmon3.ko kmon3.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kmon"
    .fill 51, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kmon"
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
str_convert:    .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
str_setmemrw:   .asciz "set_memory_rw"
str_iface_comb: .asciz "wlan_hdd_iface_combination"
str_sta_limit:  .asciz "wlan_hdd_sta_iface_limit"

fmt_addr:       .asciz "kmon3: %s @ %px\n"
fmt_bitmask:    .asciz "kmon3: bitmask patched %08x -> %08x\n"
fmt_table:      .asciz "kmon3: table[5] = %d -> %d\n"
fmt_dump:       .asciz "kmon3: iface_comb[%d]: limits=%px n_limits=%d max_if=%d types[0]=%04x\n"
fmt_patch_type: .asciz "kmon3: patched types[0]: %04x -> %04x (added monitor)\n"
fmt_ok:         .asciz "kmon3: monitor mode ENABLED\n"
fmt_err:        .asciz "kmon3: ERROR\n"

.equ ORIG_INSN,    0x528030e9
.equ PATCHED_INSN, 0x528034e9
.equ QDF_MONITOR_MODE, 4
.equ MONITOR_BIT, 0x40          /* BIT(6) = NL80211_IFTYPE_MONITOR */

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

    /* ===== Resolve symbols ===== */
    adrp x0, str_setmemrw
    add x0, x0, :lo12:str_setmemrw
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0            /* x19 = set_memory_rw */

    adrp x0, str_convert
    add x0, x0, :lo12:str_convert
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0            /* x20 = convert_nl_iftype func */

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    adrp x1, str_convert
    add x1, x1, :lo12:str_convert
    mov x2, x20
    bl printk

    adrp x0, str_iface_comb
    add x0, x0, :lo12:str_iface_comb
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x21, x0            /* x21 = iface_combination array */

    adrp x0, fmt_addr
    add x0, x0, :lo12:fmt_addr
    adrp x1, str_iface_comb
    add x1, x1, :lo12:str_iface_comb
    mov x2, x21
    bl printk

    /* ===== PATCH 1: Bitmask ===== */
    add x22, x20, #0x10
    ldr w23, [x22]

    mov w24, #PATCHED_INSN & 0xffff
    movk w24, #PATCHED_INSN >> 16, lsl #16
    cmp w23, w24
    b.eq .Lskip_bitmask     /* already patched */

    mov w25, #ORIG_INSN & 0xffff
    movk w25, #ORIG_INSN >> 16, lsl #16
    cmp w23, w25
    b.ne .Lerr

    and x0, x22, #0xfffffffffffff000
    mov x1, #1
    blr x19                 /* set_memory_rw */

    str w24, [x22]
    dc cvau, x22
    dsb ish
    ic ivau, x22
    dsb ish
    isb

    ldr w25, [x22]
    adrp x0, fmt_bitmask
    add x0, x0, :lo12:fmt_bitmask
    mov w1, w23
    mov w2, w25
    bl printk

.Lskip_bitmask:
    /* ===== PATCH 2: Lookup table ===== */
    ldr w22, [x20, #0x50]  /* ADRP instruction */
    ubfx w23, w22, #5, #19
    ubfx w24, w22, #29, #2
    orr w23, w24, w23, lsl #2
    sxtw x23, w23
    sbfx x23, x23, #0, #21
    add x24, x20, #0x50
    and x24, x24, #0xfffffffffffff000
    add x24, x24, x23, lsl #12
    add x24, x24, #0x1a8   /* x24 = table base */

    ldr w25, [x24, #20]    /* table[5] */
    cmp w25, #QDF_MONITOR_MODE
    b.eq .Lskip_table

    and x0, x24, #0xfffffffffffff000
    mov x1, #1
    blr x19

    mov w26, #QDF_MONITOR_MODE
    str w26, [x24, #20]
    add x27, x24, #20
    dc cvau, x27
    dsb ish

    ldr w26, [x24, #20]
    adrp x0, fmt_table
    add x0, x0, :lo12:fmt_table
    mov w1, w25
    mov w2, w26
    bl printk

.Lskip_table:
    /* ===== PATCH 3: iface_combination - add MONITOR to types ===== */
    /* wlan_hdd_iface_combination is an array of ieee80211_iface_combination structs.
     * Each struct is 32 bytes (padding). We need to find a combination that has
     * managed interfaces and add MONITOR bit to its types.
     *
     * The combination structure:
     *   +0x00: ptr to limits array
     *   +0x08: num_different_channels (u32)
     *   +0x0c: max_interfaces (u16)
     *   +0x0e: n_limits (u8)
     *
     * The first combination (STA only): limits = wlan_hdd_sta_iface_limit
     *   limit: max=3, types=BIT(NL80211_IFTYPE_STATION)=0x04
     *
     * We want to add BIT(6)=0x40 to the types to allow monitor+STA together.
     * Actually, simpler: add monitor bit to the first combo's types.
     */

    /* Dump first 3 combinations */
    mov x27, x21            /* x27 = current combo ptr */
    mov w28, #0             /* combo index */

.Ldump_combo:
    cmp w28, #3
    b.ge .Lpatch_combo

    ldr x22, [x27]          /* limits ptr */
    ldr w23, [x27, #8]      /* num_different_channels */
    ldrh w24, [x27, #12]    /* max_interfaces */
    ldrb w25, [x27, #14]    /* n_limits */

    /* Read types from first limit entry */
    ldrh w26, [x22, #2]     /* limit[0].types */

    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w28
    mov x2, x22
    mov w3, w25
    mov w4, w24
    mov w5, w26
    bl printk

    add x27, x27, #32      /* next combination (sizeof = 32) */
    add w28, w28, #1
    b .Ldump_combo

.Lpatch_combo:
    /* Patch the FIRST combination: add MONITOR bit to types
     * First combo is at x21, its limits ptr is at [x21]
     * The limit struct's types field is at limits_ptr + 2 */
    ldr x22, [x21]          /* limits ptr for first combo */
    ldrh w23, [x22, #2]     /* current types */

    /* Check if already has monitor */
    tst w23, #MONITOR_BIT
    b.ne .Lskip_types

    /* Make writable */
    and x0, x22, #0xfffffffffffff000
    mov x1, #1
    blr x19

    /* Add monitor bit */
    orr w24, w23, #MONITOR_BIT
    strh w24, [x22, #2]
    dc cvau, x22
    dsb ish

    /* Also increase max_interfaces from 3 to 4 to allow STA+monitor */
    ldrh w25, [x21, #12]
    add w25, w25, #1

    /* Make combo struct writable */
    and x0, x21, #0xfffffffffffff000
    mov x1, #1
    blr x19
    strh w25, [x21, #12]
    add x26, x21, #12
    dc cvau, x26
    dsb ish

    ldrh w25, [x22, #2]    /* verify */
    adrp x0, fmt_patch_type
    add x0, x0, :lo12:fmt_patch_type
    mov w1, w23
    mov w2, w25
    bl printk

.Lskip_types:
    adrp x0, fmt_ok
    add x0, x0, :lo12:fmt_ok
    bl printk

    mov w0, #0
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
