/*
 * kpatch3.S - AArch64 kernel module with 3 patches:
 *   1. nl80211_tx_mgmt+0x74: monitor TX bitmask (0x39e -> 0x3de)
 *   2. p2p_process_mgmt_tx+0xb4: subtype check bypass (CBZ->B)
 *   3. cfg80211_mlme_mgmt_tx+0x170: SA check bypass (CBNZ->NOP)
 *
 * Build: as -o kpatch3.o kpatch3.S && ld -r -o kpatch3.ko kpatch3.o
 * Load:  insmod kpatch3.ko
 * Unload: rmmod kpatch  (restores all patches)
 */

/* ============== .gnu.linkonce.this_module ============== */
.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0             /* bytes 0-23: state etc */
    .asciz "kpatch"            /* bytes 24-30: name */
    .fill 49, 1, 0             /* bytes 31-79: pad name to 56 bytes */
    .fill 256, 1, 0            /* bytes 80-335: pad to offset 0x150 */
    .quad init_module          /* offset 0x150: init function */
    .fill 440, 1, 0            /* bytes 344-783: pad to offset 0x310 */
    .quad cleanup_module       /* offset 0x310: exit function */
    .fill 40, 1, 0             /* bytes 792-831: pad to 0x340 */

/* ============== .modinfo ============== */
.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kpatch"
    .asciz "license=GPL"
    .asciz "description=Patch nl80211+p2p+cfg80211 for monitor TX"

/* ============== __versions (symbol CRCs) ============== */
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

/* ============== .rodata.str1.1 ============== */
.section .rodata.str1.1, "aMS", @progbits, 1
str_nl80211:
    .asciz "nl80211_tx_mgmt"
str_p2p_mgmt:
    .asciz "p2p_process_mgmt_tx"
str_cfg80211:
    .asciz "cfg80211_mlme_mgmt_tx"
str_patch_fn:
    .asciz "aarch64_insn_patch_text_nosync"
init_ok_msg:
    .asciz "\001kpatch: patch1 nl80211 monitor TX bitmask (0x39e->0x3de)\n"
init_ok2_msg:
    .asciz "\001kpatch: patch2 p2p_process_mgmt_tx bypass (CBZ->B)\n"
init_ok3_msg:
    .asciz "\001kpatch: patch3 cfg80211 SA check bypass (CBNZ->NOP)\n"
init_fail_msg:
    .asciz "\001kpatch: FAILED - unexpected instruction at target\n"
init_notfound_msg:
    .asciz "\001kpatch: FAILED - symbol not found\n"
init_patchfail_msg:
    .asciz "\001kpatch: FAILED - patch_text_nosync returned error\n"
exit_msg:
    .asciz "\001kpatch: all patches restored\n"

/* ============== .data ============== */
.section .data
.balign 8
saved_addr1:
    .quad 0     /* nl80211_tx_mgmt + 0x74 */
saved_addr2:
    .quad 0     /* p2p_process_mgmt_tx + 0xb4 */
saved_addr3:
    .quad 0     /* cfg80211_mlme_mgmt_tx + 0x170 */
fn_patch:
    .quad 0     /* address of aarch64_insn_patch_text_nosync */

/* ============== .init.text (init_module) ============== */
.section .init.text, "ax"
.globl init_module
.type init_module, @function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x20, x19, [sp, #16]
    stp x22, x21, [sp, #32]

    /* Look up aarch64_insn_patch_text_nosync */
    adrp x0, str_patch_fn
    add x0, x0, :lo12:str_patch_fn
    bl kallsyms_lookup_name
    cbz x0, 90f
    mov x21, x0    /* x21 = aarch64_insn_patch_text_nosync */

    /* Save patch function */
    adrp x8, fn_patch
    add x8, x8, :lo12:fn_patch
    str x21, [x8]

    /* ===== Patch 1: nl80211_tx_mgmt bitmask ===== */
    adrp x0, str_nl80211
    add x0, x0, :lo12:str_nl80211
    bl kallsyms_lookup_name
    cbz x0, 90f

    add x19, x0, #0x74

    ldr w8, [x19]
    /* Check if already patched (0x52807bcb) */
    mov w9, #0x7bcb
    movk w9, #0x5280, lsl #16
    cmp w8, w9
    b.eq 10f     /* already patched, skip */
    /* Check original (0x528073cb) */
    mov w9, #0x73cb
    movk w9, #0x5280, lsl #16
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x7bcb
    movk w1, #0x5280, lsl #16
    blr x21
    cbnz w0, 91f

10: adrp x8, saved_addr1
    add x8, x8, :lo12:saved_addr1
    str x19, [x8]

    adrp x0, init_ok_msg
    add x0, x0, :lo12:init_ok_msg
    bl printk

    /* ===== Patch 2: p2p_process_mgmt_tx bypass ===== */
    adrp x0, str_p2p_mgmt
    add x0, x0, :lo12:str_p2p_mgmt
    bl kallsyms_lookup_name
    cbz x0, 90f

    add x19, x0, #0xb4

    ldr w8, [x19]
    /* Check if already patched (0x14000045) */
    mov w9, #0x0045
    movk w9, #0x1400, lsl #16
    cmp w8, w9
    b.eq 20f     /* already patched, skip */
    /* Check original (0x340008a0) */
    mov w9, #0x08a0
    movk w9, #0x3400, lsl #16
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x0045
    movk w1, #0x1400, lsl #16
    blr x21
    cbnz w0, 91f

20: adrp x8, saved_addr2
    add x8, x8, :lo12:saved_addr2
    str x19, [x8]

    adrp x0, init_ok2_msg
    add x0, x0, :lo12:init_ok2_msg
    bl printk

    /* ===== Patch 3: cfg80211_mlme_mgmt_tx SA check bypass ===== */
    adrp x0, str_cfg80211
    add x0, x0, :lo12:str_cfg80211
    bl kallsyms_lookup_name
    cbz x0, 90f

    /* x19 = cfg80211_mlme_mgmt_tx + 0x170 */
    add x19, x0, #0x170

    ldr w8, [x19]

    /* Check if already patched (0xd503201f NOP) */
    mov w9, #0x201f
    movk w9, #0xd503, lsl #16
    cmp w8, w9
    b.eq 30f     /* already patched, skip */
    /* Expected: 0x35000168 (CBNZ W8, +0x19c) */
    mov w9, #0x0168
    movk w9, #0x3500, lsl #16
    cmp w8, w9
    b.ne 92f

    /* Patch to: 0xd503201f (NOP) - fall through to B +0x1cc at +0x174 */
    mov x0, x19
    mov w1, #0x201f
    movk w1, #0xd503, lsl #16
    blr x21
    cbnz w0, 91f

30: adrp x8, saved_addr3
    add x8, x8, :lo12:saved_addr3
    str x19, [x8]

    adrp x0, init_ok3_msg
    add x0, x0, :lo12:init_ok3_msg
    bl printk

    /* Return 0 - success */
    mov w0, #0
    b 99f

90: /* symbol not found */
    adrp x0, init_notfound_msg
    add x0, x0, :lo12:init_notfound_msg
    bl printk
    mov w0, #-1
    b 99f

91: /* patch failed */
    adrp x0, init_patchfail_msg
    add x0, x0, :lo12:init_patchfail_msg
    bl printk
    mov w0, #-1
    b 99f

92: /* bad instruction */
    adrp x0, init_fail_msg
    add x0, x0, :lo12:init_fail_msg
    bl printk
    mov w0, #-1

99: /* epilogue */
    ldp x22, x21, [sp, #32]
    ldp x20, x19, [sp, #16]
    ldp x29, x30, [sp], #64
    ret
.size init_module, . - init_module

/* ============== .exit.text (cleanup_module) ============== */
.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, @function
cleanup_module:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x20, x19, [sp, #16]

    /* Load patch function */
    adrp x0, fn_patch
    add x0, x0, :lo12:fn_patch
    ldr x20, [x0]
    cbz x20, 3f

    /* Restore patch 1: nl80211_tx_mgmt */
    adrp x0, saved_addr1
    add x0, x0, :lo12:saved_addr1
    ldr x19, [x0]
    cbz x19, 1f

    mov x0, x19
    mov w1, #0x73cb
    movk w1, #0x5280, lsl #16    /* original: 0x528073cb */
    blr x20

1:  /* Restore patch 2: p2p_process_mgmt_tx */
    adrp x0, saved_addr2
    add x0, x0, :lo12:saved_addr2
    ldr x19, [x0]
    cbz x19, 2f

    mov x0, x19
    mov w1, #0x08a0
    movk w1, #0x3400, lsl #16    /* original: 0x340008a0 */
    blr x20

2:  /* Restore patch 3: cfg80211_mlme_mgmt_tx */
    adrp x0, saved_addr3
    add x0, x0, :lo12:saved_addr3
    ldr x19, [x0]
    cbz x19, 3f

    mov x0, x19
    mov w1, #0x0168
    movk w1, #0x3500, lsl #16    /* original: 0x35000168 */
    blr x20

    /* Print */
3:  adrp x0, exit_msg
    add x0, x0, :lo12:exit_msg
    bl printk

    ldp x20, x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size cleanup_module, . - cleanup_module

/* ============== .note.Linux ============== */
.section .note.Linux, "a", @note
    .long 6         /* namesz */
    .long 0         /* descsz */
    .long 0x100     /* type: MODULE */
    .asciz "Linux"
    .balign 4

/* ============== PLT sections (required by ARM64 module loader) ============== */
.section .plt, "ax"
    .balign 8
    .space 8

.section .init.plt, "ax"
    .balign 8
    .space 8

.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
