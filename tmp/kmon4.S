/*
 * kmon4.S - Combined monitor mode enabler
 *
 * Patches 3 things:
 * 1. cfg80211_change_iface +0xd4: B.EQ → NOP (bypass interface_modes check)
 * 2. wlan_hdd_convert_nl_iftype +0x10: bitmask 0x187 → 0x1A7 (add bit 5 for MONITOR)
 * 3. wlan_hdd_convert_nl_iftype lookup table[5] = 4 (QDF_MONITOR_MODE)
 *
 * Build: as -o kmon4.o kmon4.S && ld -r -o kmon4.ko kmon4.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kmon4"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kmon4"
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
sym_cfg:        .asciz "cfg80211_change_iface"
sym_conv:       .asciz "wlan_hdd_convert_nl_iftype_to_hdd_type"
sym_patch:      .asciz "aarch64_insn_patch_text_nosync"
sym_rwx:        .asciz "set_memory_rw"

fmt_info:       .asciz "kmon4: %s @ %px\n"
fmt_p1ok:       .asciz "kmon4: PATCH1 cfg80211 B.EQ->NOP OK (was 0x%08x)\n"
fmt_p1bad:      .asciz "kmon4: PATCH1 SKIP insn mismatch: 0x%08x (expected 0x54fffbe0)\n"
fmt_p1fail:     .asciz "kmon4: PATCH1 FAIL text_patch returned %d\n"
fmt_p2ok:       .asciz "kmon4: PATCH2 bitmask OK (was 0x%08x, now 0x%08x)\n"
fmt_p2bad:      .asciz "kmon4: PATCH2 SKIP bitmask mismatch: 0x%08x\n"
fmt_p3ok:       .asciz "kmon4: PATCH3 table[5]=%d -> 4 OK\n"
fmt_p3info:     .asciz "kmon4: table @ %px, [5]=%d\n"
fmt_err:        .asciz "kmon4: ERROR sym not found: %s\n"
fmt_done:       .asciz "kmon4: ALL PATCHES APPLIED\n"
fmt_rwx:        .asciz "kmon4: set_memory_rw(%px) = %d\n"

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

    /* ========= Resolve symbols ========= */

    /* cfg80211_change_iface */
    adrp x0, sym_cfg
    add x0, x0, :lo12:sym_cfg
    bl kallsyms_lookup_name
    mov x19, x0                  /* x19 = cfg80211_change_iface */
    cbnz x0, 1f
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_cfg
    add x1, x1, :lo12:sym_cfg
    bl printk
    b .Lfail
1:
    adrp x0, fmt_info
    add x0, x0, :lo12:fmt_info
    adrp x1, sym_cfg
    add x1, x1, :lo12:sym_cfg
    mov x2, x19
    bl printk

    /* wlan_hdd_convert_nl_iftype_to_hdd_type */
    adrp x0, sym_conv
    add x0, x0, :lo12:sym_conv
    bl kallsyms_lookup_name
    mov x20, x0                  /* x20 = convert_nl_iftype */
    cbnz x0, 2f
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, sym_conv
    add x1, x1, :lo12:sym_conv
    bl printk
    b .Lfail
2:
    adrp x0, fmt_info
    add x0, x0, :lo12:fmt_info
    adrp x1, sym_conv
    add x1, x1, :lo12:sym_conv
    mov x2, x20
    bl printk

    /* aarch64_insn_patch_text_nosync */
    adrp x0, sym_patch
    add x0, x0, :lo12:sym_patch
    bl kallsyms_lookup_name
    mov x21, x0                  /* x21 = insn_patch (may be 0) */

    /* set_memory_rw */
    adrp x0, sym_rwx
    add x0, x0, :lo12:sym_rwx
    bl kallsyms_lookup_name
    mov x22, x0                  /* x22 = set_memory_rw */

    /* ========= PATCH 1: cfg80211 interface_modes bypass ========= */
    /* cfg80211_change_iface + 0xd4: expect 0x54fffbe0 (B.EQ) → 0xd503201f (NOP) */

    add x23, x19, #0xd4          /* x23 = patch address */
    ldr w24, [x23]                /* w24 = current instruction */

    /* Verify it matches */
    mov w25, #0xfbe0
    movk w25, #0x54ff, lsl #16   /* w25 = 0x54fffbe0 */
    cmp w24, w25
    b.eq .Lpatch1_go

    /* Mismatch - log and skip */
    adrp x0, fmt_p1bad
    add x0, x0, :lo12:fmt_p1bad
    mov w1, w24
    bl printk
    b .Lpatch2

.Lpatch1_go:
    /* Try aarch64_insn_patch_text_nosync first */
    cbz x21, .Lpatch1_rwx

    mov x0, x23                  /* addr */
    mov w1, #0x201f
    movk w1, #0xd503, lsl #16   /* w1 = 0xd503201f = NOP */
    blr x21                      /* call insn_patch */
    cmp w0, #0
    b.eq .Lpatch1_ok

    /* insn_patch failed, log and try set_memory_rw */
    adrp x0, fmt_p1fail
    add x0, x0, :lo12:fmt_p1fail
    /* w0 already has error code from blr */
    mov w1, w0
    bl printk

.Lpatch1_rwx:
    /* Fallback: set_memory_rw then direct write */
    cbz x22, .Lpatch2            /* skip if no set_memory_rw */

    /* Page-align the address */
    mov x0, x23
    and x0, x0, #~0xFFF          /* page-aligned addr */
    mov x1, #1                   /* 1 page */
    blr x22                      /* set_memory_rw */

    adrp x0, fmt_rwx
    add x0, x0, :lo12:fmt_rwx
    mov x1, x23
    mov w2, w0
    bl printk

    /* Direct write */
    mov w25, #0x201f
    movk w25, #0xd503, lsl #16  /* w25 = NOP */
    str w25, [x23]
    /* Flush instruction cache */
    dc cvau, x23
    dsb ish
    ic ivau, x23
    dsb ish
    isb

.Lpatch1_ok:
    adrp x0, fmt_p1ok
    add x0, x0, :lo12:fmt_p1ok
    mov w1, w24
    bl printk

    /* ========= PATCH 2: driver bitmask 0x187 → 0x1A7 ========= */
.Lpatch2:
    /* convert_nl_iftype + 0x10: expect MOV W9, #0x187 (0x528030e9) → MOV W9, #0x1A7 (0x528034e9) */
    add x23, x20, #0x10
    ldr w24, [x23]

    /* Check for 0x528030e9 */
    mov w25, #0x30e9
    movk w25, #0x5280, lsl #16
    cmp w24, w25
    b.eq .Lpatch2_go

    /* Also check if already patched (0x528034e9) */
    mov w25, #0x34e9
    movk w25, #0x5280, lsl #16
    cmp w24, w25
    b.eq .Lpatch2_done

    adrp x0, fmt_p2bad
    add x0, x0, :lo12:fmt_p2bad
    mov w1, w24
    bl printk
    b .Lpatch3

.Lpatch2_go:
    /* Make page writable */
    cbz x22, .Lpatch3
    mov x0, x23
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x22

    /* Write new instruction */
    mov w25, #0x34e9
    movk w25, #0x5280, lsl #16  /* MOV W9, #0x1A7 */
    str w25, [x23]
    dc cvau, x23
    dsb ish
    ic ivau, x23
    dsb ish
    isb

.Lpatch2_done:
    ldr w26, [x23]              /* re-read to verify */
    adrp x0, fmt_p2ok
    add x0, x0, :lo12:fmt_p2ok
    mov w1, w24
    mov w2, w26
    bl printk

    /* ========= PATCH 3: lookup table[5] = 4 ========= */
.Lpatch3:
    /* Decode ADRP at convert_nl_iftype + 0x1c to find table base */
    add x23, x20, #0x1c         /* ADRP instruction addr */
    ldr w24, [x23]              /* ADRP instruction */

    /* Extract ADRP page: immhi = bits[23:5], immlo = bits[30:29] */
    /* page = PC_page + (immhi:immlo << 12) */
    ubfx w25, w24, #5, #19      /* immhi */
    ubfx w26, w24, #29, #2      /* immlo */
    orr w25, w26, w25, lsl #2   /* immhi:immlo = 21 bits */
    /* Sign-extend 21 bits */
    sbfx x25, x25, #0, #21
    lsl x25, x25, #12           /* shift left by 12 */
    /* Add to ADRP instruction's page */
    and x26, x23, #~0xFFF       /* PC page */
    add x26, x26, x25           /* x26 = table page */

    /* Now get ADD instruction at +0x20 for the page offset */
    ldr w24, [x20, #0x20]       /* ADD instruction */
    ubfx w25, w24, #10, #12     /* imm12 */
    /* Check if shifted (bit 22) */
    tbnz w24, #22, .Lpatch3_shifted
    add x26, x26, x25           /* x26 = table base */
    b .Lpatch3_write
.Lpatch3_shifted:
    add x26, x26, x25, lsl #12

.Lpatch3_write:
    /* x26 = table base, table[5] is at +5*4 = +20 */
    add x27, x26, #20           /* addr of table[5] */

    ldr w28, [x27]              /* current value */
    adrp x0, fmt_p3info
    add x0, x0, :lo12:fmt_p3info
    mov x1, x26
    mov w2, w28
    bl printk

    /* Make page writable */
    cbz x22, .Ldone
    mov x0, x27
    and x0, x0, #~0xFFF
    mov x1, #1
    blr x22

    /* Write 4 (QDF_MONITOR_MODE) */
    mov w25, #4
    str w25, [x27]

    ldr w28, [x27]              /* verify */
    adrp x0, fmt_p3ok
    add x0, x0, :lo12:fmt_p3ok
    mov w1, w28
    /* w1 already set */
    bl printk

.Ldone:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0                   /* SUCCESS - stay loaded */
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
