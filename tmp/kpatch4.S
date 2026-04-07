/*
 * kpatch4.S - AArch64 kernel module with 5 patches:
 *   1. nl80211_tx_mgmt+0x74: monitor TX bitmask (0x39e -> 0x3de)
 *   2. p2p_process_mgmt_tx+0xb4: subtype check bypass (CBZ->B)
 *   3. cfg80211_mlme_mgmt_tx+0x170: SA check bypass (CBNZ->NOP)
 *   4. wlan_hdd_mgmt_tx+0x120: device_mode check bypass (B.HI->NOP)
 *   5. wlan_hdd_mgmt_tx+0x134: frame subtype check bypass (B.NE->NOP)
 *
 * Build: as -o kpatch4.o kpatch4.S && ld -r -o kpatch4.ko kpatch4.o
 * Load:  insmod kpatch4.ko
 * Unload: rmmod kpatch  (restores all patches)
 */

/* ============== .gnu.linkonce.this_module ============== */
.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kpatch"
    .fill 49, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

/* ============== .modinfo ============== */
.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kpatch"
    .asciz "license=GPL"
    .asciz "description=Patch nl80211+p2p+cfg80211+hdd for monitor TX inject"

/* ============== __versions ============== */
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
str_hdd_mgmt:
    .asciz "wlan_hdd_mgmt_tx"
str_patch_fn:
    .asciz "aarch64_insn_patch_text_nosync"
msg1:
    .asciz "\001kpatch: patch1 nl80211 monitor TX bitmask\n"
msg2:
    .asciz "\001kpatch: patch2 p2p bypass\n"
msg3:
    .asciz "\001kpatch: patch3 cfg80211 SA bypass\n"
msg4:
    .asciz "\001kpatch: patch4 hdd device_mode bypass\n"
msg5:
    .asciz "\001kpatch: patch5 hdd subtype bypass\n"
msg_fail:
    .asciz "\001kpatch: FAILED - unexpected instruction\n"
msg_nf:
    .asciz "\001kpatch: FAILED - symbol not found\n"
msg_pf:
    .asciz "\001kpatch: FAILED - patch call error\n"
msg_exit:
    .asciz "\001kpatch: all 5 patches restored\n"

/* ============== .data ============== */
.section .data
.balign 8
saved_addr1: .quad 0
saved_addr2: .quad 0
saved_addr3: .quad 0
saved_addr4: .quad 0
saved_addr5: .quad 0
fn_patch:    .quad 0

/* ============== .init.text ============== */
.section .init.text, "ax"
.globl init_module
.type init_module, @function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x20, x19, [sp, #16]
    stp x22, x21, [sp, #32]

    /* Look up patch function */
    adrp x0, str_patch_fn
    add x0, x0, :lo12:str_patch_fn
    bl kallsyms_lookup_name
    cbz x0, 90f
    mov x21, x0

    adrp x8, fn_patch
    add x8, x8, :lo12:fn_patch
    str x21, [x8]

    /* ===== Patch 1: nl80211_tx_mgmt+0x74 ===== */
    adrp x0, str_nl80211
    add x0, x0, :lo12:str_nl80211
    bl kallsyms_lookup_name
    cbz x0, 90f
    add x19, x0, #0x74

    ldr w8, [x19]
    mov w9, #0x73cb
    movk w9, #0x5280, lsl #16    /* expect 0x528073cb */
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x7bcb
    movk w1, #0x5280, lsl #16    /* write 0x52807bcb */
    blr x21
    cbnz w0, 91f

    adrp x8, saved_addr1
    add x8, x8, :lo12:saved_addr1
    str x19, [x8]
    adrp x0, msg1
    add x0, x0, :lo12:msg1
    bl printk

    /* ===== Patch 2: p2p_process_mgmt_tx+0xb4 ===== */
    adrp x0, str_p2p_mgmt
    add x0, x0, :lo12:str_p2p_mgmt
    bl kallsyms_lookup_name
    cbz x0, 90f
    add x19, x0, #0xb4

    ldr w8, [x19]
    mov w9, #0x08a0
    movk w9, #0x3400, lsl #16    /* expect 0x340008a0 */
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x0045
    movk w1, #0x1400, lsl #16    /* write 0x14000045 */
    blr x21
    cbnz w0, 91f

    adrp x8, saved_addr2
    add x8, x8, :lo12:saved_addr2
    str x19, [x8]
    adrp x0, msg2
    add x0, x0, :lo12:msg2
    bl printk

    /* ===== Patch 3: cfg80211_mlme_mgmt_tx+0x170 ===== */
    adrp x0, str_cfg80211
    add x0, x0, :lo12:str_cfg80211
    bl kallsyms_lookup_name
    cbz x0, 90f
    add x19, x0, #0x170

    ldr w8, [x19]
    mov w9, #0x0168
    movk w9, #0x3500, lsl #16    /* expect 0x35000168 */
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x201f
    movk w1, #0xd503, lsl #16    /* write NOP 0xd503201f */
    blr x21
    cbnz w0, 91f

    adrp x8, saved_addr3
    add x8, x8, :lo12:saved_addr3
    str x19, [x8]
    adrp x0, msg3
    add x0, x0, :lo12:msg3
    bl printk

    /* ===== Patch 4: wlan_hdd_mgmt_tx+0x120 (B.HI -> NOP) ===== */
    adrp x0, str_hdd_mgmt
    add x0, x0, :lo12:str_hdd_mgmt
    bl kallsyms_lookup_name
    cbz x0, 90f
    mov x22, x0              /* save base for patch 5 */
    add x19, x0, #0x120

    ldr w8, [x19]
    mov w9, #0x0268
    movk w9, #0x5400, lsl #16    /* expect 0x54000268 (B.HI 0x16c) */
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x201f
    movk w1, #0xd503, lsl #16    /* write NOP 0xd503201f */
    blr x21
    cbnz w0, 91f

    adrp x8, saved_addr4
    add x8, x8, :lo12:saved_addr4
    str x19, [x8]
    adrp x0, msg4
    add x0, x0, :lo12:msg4
    bl printk

    /* ===== Patch 5: wlan_hdd_mgmt_tx+0x134 (B.NE -> NOP) ===== */
    add x19, x22, #0x134

    ldr w8, [x19]
    mov w9, #0x01c1
    movk w9, #0x5400, lsl #16    /* expect 0x540001c1 (B.NE 0x16c) */
    cmp w8, w9
    b.ne 92f

    mov x0, x19
    mov w1, #0x201f
    movk w1, #0xd503, lsl #16    /* write NOP 0xd503201f */
    blr x21
    cbnz w0, 91f

    adrp x8, saved_addr5
    add x8, x8, :lo12:saved_addr5
    str x19, [x8]
    adrp x0, msg5
    add x0, x0, :lo12:msg5
    bl printk

    /* Success */
    mov w0, #0
    b 99f

90:
    adrp x0, msg_nf
    add x0, x0, :lo12:msg_nf
    bl printk
    mov w0, #-1
    b 99f

91:
    adrp x0, msg_pf
    add x0, x0, :lo12:msg_pf
    bl printk
    mov w0, #-1
    b 99f

92:
    adrp x0, msg_fail
    add x0, x0, :lo12:msg_fail
    bl printk
    mov w0, #-1

99:
    ldp x22, x21, [sp, #32]
    ldp x20, x19, [sp, #16]
    ldp x29, x30, [sp], #64
    ret
.size init_module, . - init_module

/* ============== .exit.text ============== */
.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, @function
cleanup_module:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x20, x19, [sp, #16]

    adrp x0, fn_patch
    add x0, x0, :lo12:fn_patch
    ldr x20, [x0]
    cbz x20, 5f

    /* Restore patch 1 */
    adrp x0, saved_addr1
    add x0, x0, :lo12:saved_addr1
    ldr x19, [x0]
    cbz x19, 1f
    mov x0, x19
    mov w1, #0x73cb
    movk w1, #0x5280, lsl #16
    blr x20

1:  /* Restore patch 2 */
    adrp x0, saved_addr2
    add x0, x0, :lo12:saved_addr2
    ldr x19, [x0]
    cbz x19, 2f
    mov x0, x19
    mov w1, #0x08a0
    movk w1, #0x3400, lsl #16
    blr x20

2:  /* Restore patch 3 */
    adrp x0, saved_addr3
    add x0, x0, :lo12:saved_addr3
    ldr x19, [x0]
    cbz x19, 3f
    mov x0, x19
    mov w1, #0x0168
    movk w1, #0x3500, lsl #16
    blr x20

3:  /* Restore patch 4 */
    adrp x0, saved_addr4
    add x0, x0, :lo12:saved_addr4
    ldr x19, [x0]
    cbz x19, 4f
    mov x0, x19
    mov w1, #0x0268
    movk w1, #0x5400, lsl #16
    blr x20

4:  /* Restore patch 5 */
    adrp x0, saved_addr5
    add x0, x0, :lo12:saved_addr5
    ldr x19, [x0]
    cbz x19, 5f
    mov x0, x19
    mov w1, #0x01c1
    movk w1, #0x5400, lsl #16
    blr x20

5:
    adrp x0, msg_exit
    add x0, x0, :lo12:msg_exit
    bl printk

    ldp x20, x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size cleanup_module, . - cleanup_module

/* ============== .note.Linux ============== */
.section .note.Linux, "a", @note
    .long 6
    .long 0
    .long 0x100
    .asciz "Linux"
    .balign 4

/* ============== PLT sections ============== */
.section .plt, "ax"
    .balign 8
    .space 8

.section .init.plt, "ax"
    .balign 8
    .space 8

.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
